use rule_compiler::{Atom, Operation, Operator, QueryWriter, QueryWriterFactory};
use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;
use std::os::raw::c_char;

const UNSET_OPERATOR: u8 = 0;
const EQUAL_OPERATOR: u8 = 1;
const NOT_EQUAL_OPERATOR: u8 = 2;

const UNSET_ABSOLUTE: u8 = 0;
const TRUE_ABSOLUTE: u8 = 1;
const FALSE_ABSOLUTE: u8 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct query_bprm_check_security_event_user_t {
    pub id___operator: u8,
    pub id: u32,
}

impl Default for query_bprm_check_security_event_user_t {
    fn default() -> Self {
        Self {
            id___operator: UNSET_OPERATOR,
            id: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct query_bprm_check_security_event_process_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
}

impl Default for query_bprm_check_security_event_process_t {
    fn default() -> Self {
        Self {
            name___operator: UNSET_OPERATOR,
            name: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct query_bprm_check_security_event_t {
    pub ___absolute: u8,
    pub user: query_bprm_check_security_event_user_t,
    pub process: query_bprm_check_security_event_process_t,
}

impl Default for query_bprm_check_security_event_t {
    fn default() -> Self {
        Self {
            ___absolute: UNSET_ABSOLUTE,
            user: Default::default(),
            process: Default::default(),
        }
    }
}

impl QueryStruct for query_bprm_check_security_event_t {
    fn set_absolute(&mut self, value: u8) {
        self.___absolute = value;
    }

    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String> {
        match path.as_str() {
            "user.id" => {
                let v = u32::try_from(value)
                    .map_err(|_| String::from("user.id must be a 32 bit unsigned integer"))?;
                self.user.id = v;
                self.user.id___operator = operator_to_constant(operator);
                Ok(())
            }
            _ => Err(format!("numeric field named {} not found in schema", path)),
        }
    }

    fn set_string(
        &mut self,
        path: String,
        operator: Operator,
        value: String,
    ) -> Result<(), String> {
        match path.as_str() {
            "process.name" => {
                if value.len() < 256 {
                    for (dest, src) in self.process.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.name is too long, maximum 255 characters, given value is {} characters", value.len()))
                }
            }
            _ => Err(format!("string field named {} not found in schema", path)),
        }
    }
}

pub struct BpfQueryWriter {
    table: String,
    operation: Operation,
    write_query_bprm_check_security_event_t: InnerBpfQueryWriter<query_bprm_check_security_event_t>,
}

impl BpfQueryWriter {
    fn new(table: String, operation: Operation) -> Self {
        Self {
            table: table,
            operation: operation,
            write_query_bprm_check_security_event_t: InnerBpfQueryWriter::<
                query_bprm_check_security_event_t,
            >::new(8),
        }
    }
}

impl QueryWriter for BpfQueryWriter {
    fn write_statement<'a>(
        &mut self,
        field: &'a String,
        operator: &'a Operator,
        atom: &'a Atom,
    ) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self
                .write_query_bprm_check_security_event_t
                .write_statement(field, operator, atom),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }

    fn start_new_clause(&mut self) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self
                .write_query_bprm_check_security_event_t
                .start_new_clause(),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }

    fn write_absolute(&mut self, value: bool) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self
                .write_query_bprm_check_security_event_t
                .write_absolute(value),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }
}

fn operator_to_constant(operator: Operator) -> u8 {
    match operator {
        Operator::Equal => EQUAL_OPERATOR,
        Operator::NotEqual => NOT_EQUAL_OPERATOR,
    }
}

fn absolute_to_constant(absolute: bool) -> u8 {
    match absolute {
        true => TRUE_ABSOLUTE,
        false => FALSE_ABSOLUTE,
    }
}

pub trait QueryStruct {
    fn set_absolute(&mut self, value: u8);
    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String>;
    fn set_string(&mut self, path: String, operator: Operator, value: String)
        -> Result<(), String>;
}

struct InnerBpfQueryWriter<T: QueryStruct + Default + Copy> {
    current: T,
    conditionals: Vec<T>,
    limit: usize,
}

impl<T: QueryStruct + Default + Copy> InnerBpfQueryWriter<T> {
    fn new(limit: usize) -> Self {
        Self {
            current: Default::default(),
            conditionals: vec![],
            limit: limit,
        }
    }
}

impl<T: QueryStruct + Default + Copy> QueryWriter for InnerBpfQueryWriter<T> {
    fn write_statement<'a>(
        &mut self,
        field: &'a String,
        operator: &'a Operator,
        atom: &'a Atom,
    ) -> Result<(), String> {
        match atom {
            Atom::Number(value) => self
                .current
                .set_number(field.to_string(), *operator, *value)?,
            Atom::String(value) => {
                self.current
                    .set_string(field.to_string(), *operator, value.to_string())?
            }
        };
        Ok(())
    }

    fn start_new_clause(&mut self) -> Result<(), String> {
        if self.conditionals.len() > self.limit {
            return Err(format!(
                "cannot add any more OR statements, max is {}",
                self.limit
            ));
        }
        if self.conditionals.len() == 0 {
            self.conditionals.push(self.current);
        }
        self.current = Default::default();
        Ok(())
    }

    fn write_absolute(&mut self, value: bool) -> Result<(), String> {
        if self.conditionals.len() > self.limit {
            return Err(format!(
                "cannot add any more OR statements, max is {}",
                self.limit
            ));
        }
        self.current = Default::default();
        self.current.set_absolute(absolute_to_constant(value));
        self.conditionals.push(self.current);
        Ok(())
    }
}

pub struct BpfQueryWriterFactory {}
impl QueryWriterFactory<BpfQueryWriter> for BpfQueryWriterFactory {
    fn create<'a>(&self, operation: Operation, table: &'a str) -> Result<BpfQueryWriter, String> {
        Ok(BpfQueryWriter::new(table.to_string(), operation))
    }
}
