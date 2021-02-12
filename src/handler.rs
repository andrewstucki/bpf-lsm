use probe_sys::{
    BprmCheckSecurityEvent, InodeUnlinkEvent, ProbeHandler, SerializableEvent, SerializableResult,
    TransformationHandler,
};
use std::path::Path;
use uuid::Uuid;

use crate::errors::Error;
use crate::globals::global_database;

#[derive(Copy, Clone)]
pub struct Handler {}

impl ProbeHandler<Error> for Handler {
    fn enqueue<T>(&self, event: &mut T) -> Result<(), Error>
    where
        T: SerializableEvent + std::fmt::Debug,
    {
        let db = global_database();
        let uuid = Uuid::new_v4();
        let sequence = db
            .generate_id()
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;

        let mut buffer = Uuid::encode_buffer();
        let event_id = uuid.to_hyphenated().encode_lower(&mut buffer);
        event.update_id(event_id);
        event.update_sequence(sequence);

        let data = event
            .to_bytes()
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        db.insert(
            [&sequence.to_be_bytes()[..], uuid.as_bytes()].concat(),
            data,
        )
        .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        Ok(())
    }
}

impl TransformationHandler for Handler {
    fn enrich_bprm_check_security<'a>(
        &self,
        e: &'a mut BprmCheckSecurityEvent,
    ) -> SerializableResult<&'a mut BprmCheckSecurityEvent> {
        let event = e.event.get_mut_ref();
        event.set_kind("event".to_string());
        event.set_category("process".to_string());
        event.set_field_type("start".to_string());
        event.set_module("bpf-lsm".to_string());
        event.set_provider("bprm-check-security".to_string());

        let process = e.process.get_mut_ref();
        let command_line = process.args.join(" ");
        process.set_command_line(command_line);

        Ok(e)
    }

    fn enrich_inode_unlink<'a>(
        &self,
        e: &'a mut InodeUnlinkEvent,
    ) -> SerializableResult<&'a mut InodeUnlinkEvent> {
        let event = e.event.get_mut_ref();
        event.set_kind("event".to_string());
        event.set_category("file".to_string());
        event.set_field_type("info".to_string());
        event.set_module("bpf-lsm".to_string());
        event.set_provider("inode-unlink".to_string());

        let process = e.process.get_mut_ref();
        let command_line = process.args.join(" ");
        process.set_command_line(command_line);
        
        let file = e.file.get_mut_ref();
        let file_path = file.get_path();
        let path = Path::new(file_path);
        let file_name = path.file_name().map(|f| f.to_string_lossy().to_string());
        let file_parent = path.parent().map(|f| f.to_string_lossy().to_string());
        let file_extension = path.extension().map(|f| f.to_string_lossy().to_string());

        for name in file_name {
            file.set_name(name)
        }
        for parent in file_parent {
            file.set_directory(parent)
        }
        for extension in file_extension {
            file.set_extension(extension)
        }

        Ok(e)
    }
}
