use rule_compiler::{Atom, Operation, Operator, QueryWriter, QueryWriterFactory};
use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;
use std::os::raw::c_char;
use std::fmt::Debug;

use crate::traits::QueryStruct;
use crate::helpers::absolute_to_constant;

pub(crate) struct InnerBpfQueryWriter<T: QueryStruct + Default + Copy + Debug + PartialEq> {
    module: String,
    operation: Operation,
    current: T,
    conditionals: Vec<T>,
    limit: usize,
}

impl<T: QueryStruct + Default + Copy + Debug + PartialEq> InnerBpfQueryWriter<T> {
    pub fn new(module: String, operation: Operation, limit: usize) -> Self {
        Self {
            module: module,
            operation: operation,
            current: Default::default(),
            conditionals: vec![],
            limit: limit,
        }
    }
}

impl<T: QueryStruct + Default + Copy + Debug + PartialEq> QueryWriter for InnerBpfQueryWriter<T> {
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

    fn flush(&mut self) -> Result<(), String> { Ok(()) }
}

impl<T: QueryStruct + Default + Copy + Debug + PartialEq> InnerBpfQueryWriter<T> {
    pub fn flush_probe<'a>(&mut self, probe: &'a super::Probe<'a>) -> Result<(), String> {
        let uninitialized: T = Default::default(); 
        self.conditionals.push(self.current);
        for filter in &self.conditionals {
            if *filter != uninitialized {
                probe.apply_rule(self.module.clone(), self.operation, filter.clone())
            }
        }
        Ok(())
    }
}

pub struct BpfQueryWriterFactory<'b> {
    probe: Option<&'b super::Probe<'b>>
}

impl<'b> BpfQueryWriterFactory<'b> {
    pub fn empty() -> Self {
        Self { probe: None }
    }
    
    pub fn new(probe: &'b super::Probe<'b>) -> Self {
        Self { probe: Some(probe) }
    }
}

impl<'b> QueryWriterFactory<crate::compiler::BpfQueryWriter<'b>> for BpfQueryWriterFactory<'b> {
    fn create<'a>(&self, operation: Operation, table: &'a str) -> Result<crate::compiler::BpfQueryWriter<'b>, String> {
        Ok(crate::compiler::BpfQueryWriter::new(self.probe.clone(), table.to_string(), operation))
    }
}
