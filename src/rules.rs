use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag, tag_no_case, take_while},
    character::complete::{
        alphanumeric1 as alphanumeric, char, digit1, multispace0,
    },
    combinator::{all_consuming, cut, flat_map, map, map_res, value},
    error::{context, VerboseError},
    multi::fold_many0,
    sequence::{preceded, terminated, tuple},
    IResult,
};
use byteorder::{WriteBytesExt, BigEndian};
use probe_sys::QueryType;
use std::fmt;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Operation {
    Reject,
    Filter,
}

fn parse_operation<'a>(i: &'a str) -> IResult<&'a str, Operation, VerboseError<&'a str>> {
    alt((
        map(tag_no_case("REJECT"), |_| Operation::Reject),
        map(tag_no_case("FILTER"), |_| Operation::Filter),
    ))(i)
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operation::Reject => write!(f, "REJECT"),
            Operation::Filter => write!(f, "FILTER"),
        }
    }
}

impl Operation {
  pub fn as_byte(&self) -> u8 {
      match self {
          Operation::Reject => 1,
          Operation::Filter => 2,
      }
  }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Table(String);

fn parse_table<'a>(i: &'a str) -> IResult<&'a str, Table, VerboseError<&'a str>> {
    map(
        take_while(|c: char| c == '_' || c.is_ascii_alphabetic()),
        |table: &str| Table(table.to_string()),
    )(i)
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Field(String);

fn parse_field<'a>(i: &'a str) -> IResult<&'a str, Field, VerboseError<&'a str>> {
    map(
        take_while(|c: char| c == '_' || c == '.' || c.is_ascii_alphabetic()),
        |field: &str| Field(field.to_string()),
    )(i)
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Operator {
    Equal,
    NotEqual,
}

impl Operator {
  pub fn as_byte(&self) -> u8 {
      match self {
          Operator::Equal => 1,
          Operator::NotEqual => 2,
      }
  }
}

fn parse_operator<'a>(i: &'a str) -> IResult<&'a str, Operator, VerboseError<&'a str>> {
    alt((
        map(tag("=="), |_| Operator::Equal),
        map(tag("!="), |_| Operator::NotEqual),
    ))(i)
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operator::Equal => write!(f, "=="),
            Operator::NotEqual => write!(f, "!="),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Atom {
    String(String),
    Number(u64),
    Boolean(bool),
}

fn parse_boolean<'a>(i: &'a str) -> IResult<&'a str, Atom, VerboseError<&'a str>> {
    alt((
        map(tag("true"), |_| Atom::Boolean(true)),
        map(tag("false"), |_| Atom::Boolean(false)),
    ))(i)
}

fn parse_number<'a>(i: &'a str) -> IResult<&'a str, Atom, VerboseError<&'a str>> {
    map_res(digit1, |digit_str: &str| {
        digit_str.parse::<u64>().map(Atom::Number)
    })(i)
}

fn parse_escape<'a>(i: &'a str) -> IResult<&'a str, String, VerboseError<&'a str>> {
    escaped_transform(
        alphanumeric,
        '\\',
        alt((
            value("\\", tag("\\")),
            value("\"", tag("\"")),
            value("n", tag("\n")),
        )),
    )(i)
}

fn parse_string<'a>(i: &'a str) -> IResult<&'a str, Atom, VerboseError<&'a str>> {
    map(
        context(
            "string",
            preceded(char('\"'), cut(terminated(parse_escape, char('\"')))),
        ),
        |sym_str: String| Atom::String(sym_str),
    )(i)
}

fn parse_atom<'a>(i: &'a str) -> IResult<&'a str, Atom, VerboseError<&'a str>> {
    alt((parse_number, parse_boolean, parse_string))(i)
}

impl fmt::Display for Atom {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Atom::String(s) => write!(f, "{:?}", s),
            Atom::Number(n) => write!(f, "{}", n),
            Atom::Boolean(b) => write!(f, "{}", b),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Constant(Atom),
    Statement(Field, Operator, Atom),
}

fn parse_constant<'a>(i: &'a str) -> IResult<&'a str, Expression, VerboseError<&'a str>> {
    map(parse_boolean, |atom| Expression::Constant(atom))(i)
}

fn parse_statement<'a>(i: &'a str) -> IResult<&'a str, Expression, VerboseError<&'a str>> {
    map(
        tuple((
            terminated(parse_field, multispace0),
            terminated(parse_operator, multispace0),
            terminated(parse_atom, multispace0),
        )),
        |(field, operator, atom)| Expression::Statement(field, operator, atom),
    )(i)
}

fn parse_expression<'a>(i: &'a str) -> IResult<&'a str, Expression, VerboseError<&'a str>> {
    alt((parse_statement, parse_constant))(i)
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expression::Constant(atom) => write!(f, "{}", atom),
            Expression::Statement(field, operator, atom) => {
                write!(f, "{} {} {}", field, operator, atom)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AndClause {
    pub truthy: bool,
    pub value: bool,
    pub expressions: Vec<Expression>,
}

impl AndClause {
    pub fn new(expression: Expression) -> Self {
        let mut instance = Self {
            truthy: false,
            value: false,
            expressions: vec![],
        };
        instance.add(expression);
        instance
    }

    pub fn try_evaluate(&self) -> Option<bool> {
        if self.truthy {
            return Some(self.value);
        }
        return None;
    }

    pub fn try_reduce(&self) -> Option<Expression> {
        if self.expressions.len() == 1 {
            return Some(self.expressions[0].clone());
        }
        return None;
    }

    pub fn add(&mut self, expression: Expression) -> &mut Self {
        if self.truthy && !self.value {
            // we have a false in our sub-expressions
            // so we'll always evaluate to false, no-op
            return self;
        }
        let (truthy, value) = match expression {
            Expression::Constant(Atom::Boolean(b)) => (true, b),
            _ => (false, false),
        };
        if truthy {
            if !value {
                // we're adding a false value, so
                // clear ourselves and set truth/value
                self.expressions.clear();
                self.truthy = true;
                self.value = false;
                return self;
            }
            if self.expressions.len() == 0 {
                self.truthy = true;
                self.value = true;
            }
            // we're adding a true value, no-op
            return self;
        }
        self.truthy = false;
        let mut conflicts = false;
        for expr in &self.expressions {
            if expr == &expression {
                // we have an identical expression, no-op
                return self;
            }
            match (expr, &expression) {
                (
                    Expression::Statement(ref field1, Operator::Equal, _),
                    Expression::Statement(ref field2, Operator::Equal, _),
                ) => {
                    if field1 == field2 {
                        // we have an expression on the same field and same equality operator
                        // which conflicts
                        conflicts = true;
                        break;
                    }
                }
                (
                    Expression::Statement(ref field1, Operator::Equal, value1),
                    Expression::Statement(ref field2, Operator::NotEqual, value2),
                ) => {
                    if field1 == field2 && value1 == value2 {
                        // we have an expression on the same field and different equality operator
                        // with same value which conflicts
                        conflicts = true;
                        break;
                    }
                }
                (
                    Expression::Statement(ref field1, Operator::NotEqual, value1),
                    Expression::Statement(ref field2, Operator::Equal, value2),
                ) => {
                    if field1 == field2 && value1 == value2 {
                        // we have an expression on the same field and different equality operator
                        // with same value which conflicts
                        conflicts = true;
                        break;
                    }
                }
                _ => continue,
            }
        }
        if conflicts {
            self.expressions.clear();
            self.truthy = true;
            self.value = false;
            return self;
        }
        // we have a normal expression, add it
        self.expressions.push(expression);
        self
    }

    pub fn contains(&self, other: &Self) -> bool {
        // same as equality minus the length check and reversed
        self.truthy == other.truthy
            && self.value == other.value
            && other
                .expressions
                .iter()
                .find(|&x| !self.expressions.contains(x))
                .is_none()
    }

    pub fn take(&mut self, other: &Self) {
        self.expressions = other.expressions.clone()
    }

    pub fn encode(&self, fields: Vec<(String, QueryType)>) -> Vec<u8> {
      // this should only be called after validation and by the parent or clause
      let mut writer = Vec::new();
      for (f, t) in &fields {
        match (t, self.expressions.iter().find(|&e| match e {
          Expression::Statement(Field(field), _, _) => field == f,
          _ => false
        })) {
          (QueryType::Number, Some(Expression::Statement(_, operation, Atom::Number(n)))) => {
              // number fields always have 72 bits
              writer.write_u8(operation.as_byte()).unwrap();
              // always encode as a 64 bit integer
              writer.write_u64::<BigEndian>(*n).unwrap();
          },
          (QueryType::String(n), Some(Expression::Statement(_, operation, Atom::String(value)))) => {
              // string fields always have 4 + n bits
              writer.write_u8(operation.as_byte()).unwrap();
              // number fields always have 72 bits
              writer.append(&mut value.clone().into_bytes());
              // pad the rest with nul values
              for _ in value.len()..*n {
                writer.write_u8(0).unwrap();
              }
          },
          _ => {
            writer.write_u8(0).unwrap(); // nul byte == no operation
          },
        }
      }
      writer
    }
}

impl PartialEq for AndClause {
    fn eq(&self, other: &Self) -> bool {
        // check elements without order consideration
        self.truthy == other.truthy
            && self.value == other.value
            && self.expressions.len() == other.expressions.len()
            && self
                .expressions
                .iter()
                .find(|&x| !other.expressions.contains(x))
                .is_none()
    }
}

impl fmt::Display for AndClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.truthy {
            write!(f, "{}", self.value)
        } else {
            write!(
                f,
                "{}",
                self.expressions
                    .iter()
                    .map(|expr| expr.to_string())
                    .collect::<Vec<String>>()
                    .join(" AND ")
            )
        }
    }
}

fn parse_and_clause<'a>(i: &'a str) -> IResult<&'a str, AndClause, VerboseError<&'a str>> {
    flat_map(
        terminated(parse_expression, multispace0),
        |initial: Expression| {
            fold_many0(
                preceded(
                    terminated(tag_no_case("AND"), multispace0),
                    terminated(parse_expression, multispace0),
                ),
                AndClause::new(initial),
                |mut combined: AndClause, expression: Expression| {
                    combined.add(expression);
                    combined
                },
            )
        },
    )(i)
}

#[derive(Debug, PartialEq, Clone)]
pub struct OrClause {
    pub truthy: bool,
    pub value: bool,
    pub subclauses: Vec<AndClause>,
}

impl OrClause {
    pub fn new(subclause: AndClause) -> Self {
        let mut instance = Self {
            truthy: false,
            value: false,
            subclauses: vec![],
        };
        instance.add(subclause);
        instance
    }

    pub fn add(&mut self, subclause: AndClause) -> &mut Self {
        if self.truthy && self.value {
            // we have a true in our sub-expressions
            // so we'll always evaluate to true, no-op
            return self;
        }
        let (truthy, value) = match subclause.try_evaluate() {
            Some(b) => (true, b),
            None => (false, false),
        };
        if truthy {
            if value {
                // we're adding a true value, so
                // clear ourselves and set truth/value
                self.subclauses.clear();
                self.truthy = true;
                self.value = true;
                return self;
            }
            if self.subclauses.len() == 0 {
                self.truthy = true;
                self.value = false;
            }
            // we're adding a false value, no-op
            return self;
        }
        self.truthy = false;
        let mut reduced = false;
        for clause in &mut self.subclauses {
            if clause.contains(&subclause) {
                // we have a contained subclause, no-op
                return self;
            }
            if subclause.contains(clause) {
                // we have a superset, merge them
                clause.take(&subclause);
                return self;
            }
            match (clause.try_reduce(), subclause.try_reduce()) {
                (Some(expression1), Some(expression2)) => match (expression1, expression2) {
                    (
                        Expression::Statement(ref field1, Operator::Equal, _),
                        Expression::Statement(ref field2, Operator::NotEqual, _),
                    ) => {
                        if field1 == field2 {
                            // we have an expression on the same field that is all encompasing
                            reduced = true;
                            break;
                        }
                    }
                    (
                        Expression::Statement(ref field1, Operator::NotEqual, _),
                        Expression::Statement(ref field2, Operator::Equal, _),
                    ) => {
                        if field1 == field2 {
                            // we have an expression on the same field that is all encompasing
                            reduced = true;
                            break;
                        }
                    }
                    _ => continue,
                },
                _ => continue,
            }
        }
        if reduced {
            self.subclauses.clear();
            self.truthy = true;
            self.value = true;
            return self;
        }
        // we have a normal subclause, add it
        self.subclauses.push(subclause);
        self
    }

    pub fn encode(&self, fields: Vec<(String, QueryType)>) -> (Vec<u8>, Vec<Vec<u8>>) { // (metadata, encoding)
        let mut writer = Vec::new();
        let mut meta = 0; // normal encoding
        if self.truthy {
          if self.value {
            meta = 1;
          } else {
            meta = 2;
          }
        }
        writer.write_u8(meta).unwrap();
        let size = self.subclauses.len() as u64;
        writer.write_u64::<BigEndian>(size).unwrap();
        // writer should always be 72 bits
        return (writer, self.subclauses.iter().map(|s| s.encode(fields.clone())).collect())        
    }
}

impl fmt::Display for OrClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.truthy {
            write!(f, "{}", self.value)
        } else {
            write!(
                f,
                "{}",
                self.subclauses
                    .iter()
                    .map(|clause| clause.to_string())
                    .collect::<Vec<String>>()
                    .join(" OR ")
            )
        }
    }
}

fn parse_or_clause<'a>(i: &'a str) -> IResult<&'a str, OrClause, VerboseError<&'a str>> {
    // an or takes precedence, so we parse runs of ands first
    flat_map(parse_and_clause, |initial: AndClause| {
        fold_many0(
            preceded(terminated(tag_no_case("OR"), multispace0), parse_and_clause),
            OrClause::new(initial),
            |mut combined: OrClause, subexpression: AndClause| {
                combined.add(subexpression);
                combined
            },
        )
    })(i)
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rule {
    operation: Operation,
    table: Table,
    clause: OrClause,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} WHEN {}", self.operation, self.table, self.clause)
    }
}

impl Rule {
    fn validate(&self, fields: Vec<(String, QueryType)>) -> bool {
        self.clause
            .subclauses
            .iter()
            .find(|&clause| {
                clause
                    .expressions
                    .iter()
                    .find(|&expression| {
                        match expression {
                            Expression::Statement(Field(field), _, Atom::String(value)) => {
                                for (f, t) in &fields {
                                    if f != field {
                                        continue;
                                    }
                                    match t {
                                        QueryType::String(n) => {
                                          // include the nul byte
                                          // so, due to inverted logic, constraint
                                          // is query value length < allowed length (minus nul)
                                          return value.len() >= *n
                                        },
                                        _ => return true,
                                    }
                                }
                                return true;
                            }
                            Expression::Statement(Field(field), _, Atom::Number(_)) => {
                                !fields.contains(&(field.to_string(), QueryType::Number))
                            }
                            _ => false,
                        }
                    })
                    .is_some()
            })
            .is_none()
    }

    pub fn encode(&self, fields: Vec<(String, QueryType)>) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
        if !self.validate(fields.clone()) {
          return Err(String::from("fields are invalid"))
        }
        let (mut metadata, clauses) = self.clause.encode(fields);
        // append the operation type
        metadata.write_u8(self.operation.as_byte()).unwrap();
        Ok((metadata, clauses))
    }
}

fn parse_rule<'a>(i: &'a str) -> IResult<&'a str, Rule, VerboseError<&'a str>> {
    all_consuming(map(
        tuple((
            terminated(parse_operation, multispace0),
            terminated(parse_table, multispace0),
            preceded(
                terminated(tag_no_case("WHEN"), multispace0),
                terminated(parse_or_clause, multispace0),
            ),
        )),
        |(operation, table, clause)| Rule {
            operation: operation,
            table: table,
            clause: clause,
        },
    ))(i)
}

pub fn compile<'a>(i: &'a str) -> Result<Rule, String> {
    parse_rule(i)
        .map_err(|e| e.to_string())
        .map(|(_, rule)| rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile() {
        assert!(compile(r#"FOO foo_bar_baz WHEN x==a"#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN x=="1\\"""#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN x==a"#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN "x"==a"#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN "x""#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN x"#).is_err());
        assert!(compile(r#"REJECT foo_bar_baz WHEN"#).is_err());
        assert_eq!(
            compile(r#"reject foo_bar_baz when true"#).map(|c| c.to_string()),
            Ok(String::from(r#"REJECT foo_bar_baz WHEN true"#))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x=="1\"""#).map(|c| c.to_string()),
            Ok(String::from(r#"REJECT foo_bar_baz WHEN x == "1\"""#))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 1"))
        );
        // optimizing
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND false OR true"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN true"))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN false AND false AND false OR true"#)
                .map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN true"))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN true AND false OR x==1"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 1"))
        );
        // precedence
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN false AND x==1 AND true OR true AND x==2"#)
                .map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 2"))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN true AND x==1 AND true or true AND x==2 AND true"#)
                .map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 1 OR x == 2"))
        );
        // equivalent condition
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND x==1"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 1"))
        );
        // equivalent field
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND x==2"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN false"))
        );
        // exclusive field
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND x!=1"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN false"))
        );
        // inclusive field
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 OR x!=1"#).map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN true"))
        );
        // complex
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN true AND x==1 AND true or true AND x!=1 AND true"#)
                .map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN true"))
        );
        // re-ordered
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND y==2 OR y==2 AND x==1"#)
                .map(|c| c.to_string()),
            Ok(String::from("REJECT foo_bar_baz WHEN x == 1 AND y == 2"))
        );
        // subset
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 AND y==2 OR  x==1 and y==2 AND z==3"#)
                .map(|c| c.to_string()),
            Ok(String::from(
                "REJECT foo_bar_baz WHEN x == 1 AND y == 2 AND z == 3"
            ))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 and y==2 AND z==3 OR x==1 AND y==2 OR x==1 and y==2 and z==3 and v==4"#)
                .map(|c| c.to_string()),
            Ok(String::from(
                "REJECT foo_bar_baz WHEN x == 1 AND y == 2 AND z == 3 AND v == 4"
            ))
        );
        assert_eq!(
            compile(r#"REJECT foo_bar_baz WHEN x==1 and y==2 AND z==3 OR x==1 AND y==2 OR x==1 and y==2 and z==3 and x==2"#)
                .map(|c| c.to_string()),
            Ok(String::from(
                "REJECT foo_bar_baz WHEN x == 1 AND y == 2 AND z == 3"
            ))
        );
    }

    #[test]
    fn test_encoding() {
        let rule = compile(r#"REJECT foo_bar_baz WHEN x==1 and y==2 AND z==3 OR x==1 AND y==2 OR x==1 and y==2 and z==3 and a=="2""#).unwrap();
        assert!(rule.encode(vec!(
            (String::from("x"), QueryType::Number),
            (String::from("y"), QueryType::Number),
            (String::from("z"), QueryType::Number),
            (String::from("a"), QueryType::String(2))
        )).is_ok());
        assert!(rule.encode(vec!(
            (String::from("x"), QueryType::Number),
            (String::from("y"), QueryType::Number)
        )).is_err());
        assert!(rule.encode(vec!(
            (String::from("x"), QueryType::Number),
            (String::from("y"), QueryType::String(1)),
            (String::from("z"), QueryType::Number),
        )).is_err());
        assert!(rule.encode(vec!(
            (String::from("x"), QueryType::Number),
            (String::from("y"), QueryType::Number),
            (String::from("z"), QueryType::Number),
            (String::from("a"), QueryType::String(0))
        )).is_err());
    }
}
