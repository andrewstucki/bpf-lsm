#![allow(clippy::all)]

use protobuf::Message;

use crate::errors::SerializableResult;
use crate::struct_pb::*;
use crate::traits::SerializableEvent;

pub trait TransformationHandler {
    fn enrich_bprm_check_security<'a>(&self, e: &'a mut BprmCheckSecurityEvent) -> SerializableResult<&'a mut BprmCheckSecurityEvent>;
    fn enrich_inode_unlink<'a>(&self, e: &'a mut InodeUnlinkEvent) -> SerializableResult<&'a mut InodeUnlinkEvent>;
}

pub struct Transformer<T> {
    handler: T,
}

impl<T: TransformationHandler> Transformer<T> {
    pub fn new(handler: T) -> Self {
        Self { handler: handler }
    }

    pub fn transform(&self, data: Vec<u8>) -> SerializableResult<(String, String)> {
        let e = Event::parse_from_bytes(&data).unwrap();
        match e.get_event_type() {
            event::EventType::BPRMCHECKSECURITYEVENT => {
                let json = self.handler.enrich_bprm_check_security((&mut e.bprm_check_security_event_t.unwrap()).enrich_common()?)?.to_json()?;
                Ok((String::from("bprm_check_security"), json))
            },
            event::EventType::INODEUNLINKEVENT => {
                let json = self.handler.enrich_inode_unlink((&mut e.inode_unlink_event_t.unwrap()).enrich_common()?)?.to_json()?;
                Ok((String::from("inode_unlink"), json))
            },
        }
    }
}