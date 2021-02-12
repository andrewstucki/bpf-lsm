use protobuf::Message;

use crate::errors::SerializableResult;
use crate::struct_pb::*;
use crate::traits::SerializableEvent;

pub trait TransformationHandler {
    fn enrich_bprm_check_security<'a>(&self, e: &'a mut BprmCheckSecurityEvent) -> SerializableResult<&'a mut BprmCheckSecurityEvent>;
    fn enrich_path_rename<'a>(&self, e: &'a mut PathRenameEvent) -> SerializableResult<&'a mut PathRenameEvent>;
    fn enrich_inode_unlink<'a>(&self, e: &'a mut InodeUnlinkEvent) -> SerializableResult<&'a mut InodeUnlinkEvent>;
}

pub struct Transformer<T> {
    handler: T,
}

impl<T: TransformationHandler> Transformer<T> {
    pub fn new(handler: T) -> Self {
        Self { handler: handler }
    }

    pub fn transform(&self, data: Vec<u8>) -> SerializableResult<String> {
        let e = Event::parse_from_bytes(&data).unwrap();
        match e.get_event_type() {
            event::EventType::BPRMCHECKSECURITYEVENT => {
                self.handler.enrich_bprm_check_security((&mut e.bprm_check_security_event_t.unwrap()).enrich_common()?)?.to_json()
            },
            event::EventType::PATHRENAMEEVENT => {
                self.handler.enrich_path_rename((&mut e.path_rename_event_t.unwrap()).enrich_common()?)?.to_json()
            },
            event::EventType::INODEUNLINKEVENT => {
                self.handler.enrich_inode_unlink((&mut e.inode_unlink_event_t.unwrap()).enrich_common()?)?.to_json()
            },
        }
    }
}