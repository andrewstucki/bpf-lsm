use rule_compiler::QueryWriter;
// pub trait QueryWriter {
//     // called on each statement of an and clause
//     fn write_statement<'a>(
//         &mut self,
//         field: &'a String,
//         operator: &'a Operator,
//         atom: &'a Atom,
//     ) -> Result<(), String>;
//     // // called to start a new and clause
//     fn start_new_clause(&mut self) -> Result<(), String>;
//     // // called if the logic is reduced to t/f
//     fn write_absolute(&mut self, value: bool) -> Result<(), String>;
//     // // called to begin a new rule
//     fn start_new_rule<'a>(&mut self, operation: Operation, table: &'a str) -> Result<(), String>;
// }
