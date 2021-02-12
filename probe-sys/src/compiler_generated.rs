use rule_compiler::{Atom, Operation, Operator, QueryWriter};
use std::convert::TryFrom;
use std::os::raw::c_char;

use crate::constants::UNSET_OPERATOR;
use crate::helpers::operator_to_constant;
use crate::query_writer::InnerBpfQueryWriter;
use crate::traits::QueryStruct;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_bprm_check_security_event_process_parent_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
}

impl Default for query_bpf_bprm_check_security_event_process_parent_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_bprm_check_security_event_process_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
    pub parent: query_bpf_bprm_check_security_event_process_parent_t,
}

impl Default for query_bpf_bprm_check_security_event_process_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_bprm_check_security_event_user_t {
    pub id___operator: u8,
    pub id: u32,
}

impl Default for query_bpf_bprm_check_security_event_user_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_bprm_check_security_event_t {
    pub ___absolute: u8,
    pub process: query_bpf_bprm_check_security_event_process_t,
    pub user: query_bpf_bprm_check_security_event_user_t,
}

impl Default for query_bpf_bprm_check_security_event_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl QueryStruct for query_bpf_bprm_check_security_event_t {
    fn set_absolute(&mut self, value: u8) {
        self.___absolute = value;
    }

    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String> {
        match path.as_str() {
            "user.id" => {
                if self.user.id___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                let v = u32::try_from(value).map_err(|_| String::from("user.id must be a u32"))?;
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
            "process.parent.name" => {
                if self.process.parent.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.parent.executable" => {
                if self.process.parent.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.name" => {
                if self.process.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.executable" => {
                if self.process.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            _ => Err(format!("string field named {} not found in schema", path)),
        }
    }

    fn flush<'a>(&mut self, _probe: &'a super::Probe<'a>) -> Result<(), String> {
        Ok(())
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_rename_event_process_parent_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
}

impl Default for query_bpf_path_rename_event_process_parent_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_rename_event_process_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
    pub parent: query_bpf_path_rename_event_process_parent_t,
}

impl Default for query_bpf_path_rename_event_process_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_rename_event_user_t {
    pub id___operator: u8,
    pub id: u32,
}

impl Default for query_bpf_path_rename_event_user_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_rename_event_t {
    pub ___absolute: u8,
    pub process: query_bpf_path_rename_event_process_t,
    pub user: query_bpf_path_rename_event_user_t,
}

impl Default for query_bpf_path_rename_event_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl QueryStruct for query_bpf_path_rename_event_t {
    fn set_absolute(&mut self, value: u8) {
        self.___absolute = value;
    }

    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String> {
        match path.as_str() {
            "user.id" => {
                if self.user.id___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                let v = u32::try_from(value).map_err(|_| String::from("user.id must be a u32"))?;
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
            "process.parent.name" => {
                if self.process.parent.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.parent.executable" => {
                if self.process.parent.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.name" => {
                if self.process.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.executable" => {
                if self.process.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            _ => Err(format!("string field named {} not found in schema", path)),
        }
    }

    fn flush<'a>(&mut self, _probe: &'a super::Probe<'a>) -> Result<(), String> {
        Ok(())
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_unlink_event_process_parent_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
}

impl Default for query_bpf_path_unlink_event_process_parent_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_unlink_event_process_t {
    pub name___operator: u8,
    pub name: [c_char; 256],
    pub executable___operator: u8,
    pub executable: [c_char; 256],
    pub parent: query_bpf_path_unlink_event_process_parent_t,
}

impl Default for query_bpf_path_unlink_event_process_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_unlink_event_user_t {
    pub id___operator: u8,
    pub id: u32,
}

impl Default for query_bpf_path_unlink_event_user_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct query_bpf_path_unlink_event_t {
    pub ___absolute: u8,
    pub process: query_bpf_path_unlink_event_process_t,
    pub user: query_bpf_path_unlink_event_user_t,
}

impl Default for query_bpf_path_unlink_event_t {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl QueryStruct for query_bpf_path_unlink_event_t {
    fn set_absolute(&mut self, value: u8) {
        self.___absolute = value;
    }

    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String> {
        match path.as_str() {
            "user.id" => {
                if self.user.id___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                let v = u32::try_from(value).map_err(|_| String::from("user.id must be a u32"))?;
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
            "process.parent.name" => {
                if self.process.parent.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.parent.executable" => {
                if self.process.parent.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.parent.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.parent.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.parent.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.name" => {
                if self.process.name___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.name.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.name___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.name is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            "process.executable" => {
                if self.process.executable___operator != UNSET_OPERATOR {
                    // we can only hold a single condition per variable for now
                    return Err(format!("{} already in condition", path));
                }
                if value.len() < 256 {
                    for (dest, src) in self.process.executable.iter_mut().zip(value.as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    self.process.executable___operator = operator_to_constant(operator);
                    Ok(())
                } else {
                    Err(format!("process.executable is too long, maximum 256 characters, given value is {} characters", value.len()))
                }
            },
            _ => Err(format!("string field named {} not found in schema", path)),
        }
    }

    fn flush<'a>(&mut self, _probe: &'a super::Probe<'a>) -> Result<(), String> {
        Ok(())
    }
}

pub struct BpfQueryWriter<'a> {
    table: String,
    write_query_bprm_check_security_event_t: InnerBpfQueryWriter<query_bpf_bprm_check_security_event_t>,
    write_query_path_rename_event_t: InnerBpfQueryWriter<query_bpf_path_rename_event_t>,
    write_query_path_unlink_event_t: InnerBpfQueryWriter<query_bpf_path_unlink_event_t>,
    probe: Option<&'a super::Probe<'a>>,
}

impl<'a> BpfQueryWriter<'a> {
    pub fn new(probe: Option<&'a super::Probe>, table: String, operation: Operation) -> Self {
        Self {
            table: table,
            write_query_bprm_check_security_event_t: InnerBpfQueryWriter::<query_bpf_bprm_check_security_event_t>::new(
                "bprm_check_security".into(),
                operation,
                8,
            ),
            write_query_path_rename_event_t: InnerBpfQueryWriter::<query_bpf_path_rename_event_t>::new(
                "path_rename".into(),
                operation,
                8,
            ),
            write_query_path_unlink_event_t: InnerBpfQueryWriter::<query_bpf_path_unlink_event_t>::new(
                "path_unlink".into(),
                operation,
                8,
            ),
            probe: probe,
        }
    }
}

impl<'b> QueryWriter for BpfQueryWriter<'b> {
    fn write_statement<'a>(
        &mut self,
        field: &'a String,
        operator: &'a Operator,
        atom: &'a Atom,
    ) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self.write_query_bprm_check_security_event_t.write_statement(field, operator, atom),
            "path_rename" => self.write_query_path_rename_event_t.write_statement(field, operator, atom),
            "path_unlink" => self.write_query_path_unlink_event_t.write_statement(field, operator, atom),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }

    fn start_new_clause(&mut self) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self.write_query_bprm_check_security_event_t.start_new_clause(),
            "path_rename" => self.write_query_path_rename_event_t.start_new_clause(),
            "path_unlink" => self.write_query_path_unlink_event_t.start_new_clause(),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }

    fn write_absolute(&mut self, value: bool) -> Result<(), String> {
        match self.table.as_str() {
            "bprm_check_security" => self.write_query_bprm_check_security_event_t.write_absolute(value),
            "path_rename" => self.write_query_path_rename_event_t.write_absolute(value),
            "path_unlink" => self.write_query_path_unlink_event_t.write_absolute(value),
            _ => Err(format!("invalid table name {}", self.table)),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self.probe {
            Some(probe) => match self.table.as_str() {
                "bprm_check_security" => self.write_query_bprm_check_security_event_t.flush_probe(probe),
                "path_rename" => self.write_query_path_rename_event_t.flush_probe(probe),
                "path_unlink" => self.write_query_path_unlink_event_t.flush_probe(probe),
                _ => Err(format!("invalid table name {}", self.table)),
            },
            _ => Ok(())
        }
    }
}