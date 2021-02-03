use std::path::Path;
use uuid::Uuid;
use probe_sys::{BprmCheckSecurityEvent, ProbeHandler, SerializableEvent, SerializableResult, TransformationHandler};

use crate::errors::Error;
use crate::globals::global_database;

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
        
        let executable = process.get_executable();
        // override the name of the process since we're capturing
        // an exec and the process is going to have the forking
        // process name initially
        for name in Path::new(executable).file_name().map(|f| {
            f.to_string_lossy().to_string()
        }) {
            process.set_name(name);
        }

        Ok(e)
    }
}
