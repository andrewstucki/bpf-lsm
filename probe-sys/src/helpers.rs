use std::ffi::CStr;
use std::os::raw::c_char;
use rule_compiler::{Atom, Operation, Operator, QueryWriter, QueryWriterFactory};
use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;
use std::fmt::Debug;

use crate::constants::{EQUAL_OPERATOR, NOT_EQUAL_OPERATOR, TRUE_ABSOLUTE, FALSE_ABSOLUTE};

pub(crate) fn transform_string(val: Vec<c_char>) -> String {
  unsafe { CStr::from_ptr(val.as_ptr()).to_string_lossy().into_owned() }
}

pub(crate) fn convert_string_array<T>(size: u64, arr: Vec<T>) -> Vec<String>
where T: Into<Vec<c_char>> + Copy {
    unsafe { 
        let mut strings = vec![];
        for x in 0..size {
            let ptr: Vec<c_char> = arr[x as usize].into();
            let var = CStr::from_ptr(ptr.as_ptr());
            let printable = var.to_string_lossy().into_owned();
            strings.push(printable)
        }
        strings
    }
}

pub(crate) fn int_to_string(v: u32) -> String {
  v.to_string()
}

pub(crate) fn operator_to_constant(operator: Operator) -> u8 {
    match operator {
        Operator::Equal => EQUAL_OPERATOR,
        Operator::NotEqual => NOT_EQUAL_OPERATOR,
    }
}

pub(crate) fn absolute_to_constant(absolute: bool) -> u8 {
    match absolute {
        true => TRUE_ABSOLUTE,
        false => FALSE_ABSOLUTE,
    }
}
