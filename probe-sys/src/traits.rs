use rule_compiler::{Operator, Operation};

use crate::errors::SerializableResult;

pub trait SerializableEvent {
    fn to_json(&self) -> SerializableResult<String>;
    fn to_bytes(&self) -> SerializableResult<Vec<u8>>;
    fn enrich_common<'a>(&'a mut self) -> SerializableResult<&'a mut Self>;
    fn update_id(&mut self, id: &mut str);
    fn update_sequence(&mut self, seq: u64);
    fn suffix(&self) -> &'static str;
}

pub trait QueryStruct {
    fn set_absolute(&mut self, value: u8);
    fn set_number(&mut self, path: String, operator: Operator, value: u64) -> Result<(), String>;
    fn set_string(&mut self, path: String, operator: Operator, value: String)
        -> Result<(), String>;
    fn flush<'a>(&mut self, probe: &'a super::Probe<'a>) -> Result<(), String>;
}

pub(crate) trait QueryFlusher {
    fn apply_rule<T: QueryStruct>(&self, module: String, operation: Operation, rule: T);
}
