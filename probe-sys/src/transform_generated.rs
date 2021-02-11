use protobuf::Message;

use crate::struct_pb::*;
use crate::errors::SerializableResult;
use crate::traits::SerializableEvent;

pub trait TransformationHandler {
    fn enrich_bprm_check_security<'a>(&self, e: &'a mut BprmCheckSecurityEvent) -> SerializableResult<&'a mut BprmCheckSecurityEvent>;
}

pub struct Transformer<T> {
    handler: T,
}

impl<T: TransformationHandler> Transformer<T> {
  pub fn new(handler: T) -> Self {
      Self {
          handler: handler,
      }
  }

  pub fn transform(&self, data: Vec<u8>) -> SerializableResult<String> {
      let e = Event::parse_from_bytes(&data).unwrap();
      match e.get_event_type() {
          event::EventType::BPRMCHECKSECURITYEVENT => {
              self.handler.enrich_bprm_check_security((&mut e.bprm_check_security_event_t.unwrap()).enrich_common()?)?.to_json()
          },
      }
  }  
}