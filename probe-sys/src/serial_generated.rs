use machine_uid;
use pnet::datalink::interfaces;
use protobuf::json::print_to_string;
use protobuf::Message;
use sha2::Digest;
use sysinfo::{System, SystemExt};
use users::{Groups, Users};

use crate::errors::{SerializableResult, SerializationError};
use crate::ffi_generated as ffi;
use crate::helpers::*;
use crate::struct_pb::*;
use crate::traits::SerializableEvent;

impl From<ffi::bprm_check_security_event_event_t> for BprmCheckSecurityEventEvent {
    fn from(e: ffi::bprm_check_security_event_event_t) -> Self {
        let mut event = Self::default();
        event.set_action(transform_string(e.action.into()));
        event
    }
}

impl From<ffi::bprm_check_security_event_process_parent_t> for BprmCheckSecurityEventProcessParent {
    fn from(e: ffi::bprm_check_security_event_process_parent_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_args_count(e.args_count);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.set_ppid(e.ppid);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.set_executable(transform_string(e.executable.into()));
        event
    }
}

impl From<ffi::bprm_check_security_event_process_t> for BprmCheckSecurityEventProcess {
    fn from(e: ffi::bprm_check_security_event_process_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_ppid(e.ppid);
        event.set_executable(transform_string(e.executable.into()));
        event.set_args_count(e.args_count);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.parent = Some(e.parent.into()).into();
        event
    }
}

impl From<ffi::bprm_check_security_event_user_group_t> for BprmCheckSecurityEventUserGroup {
    fn from(e: ffi::bprm_check_security_event_user_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::bprm_check_security_event_user_effective_group_t> for BprmCheckSecurityEventUserEffectiveGroup {
    fn from(e: ffi::bprm_check_security_event_user_effective_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::bprm_check_security_event_user_effective_t> for BprmCheckSecurityEventUserEffective {
    fn from(e: ffi::bprm_check_security_event_user_effective_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event
    }
}

impl From<ffi::bprm_check_security_event_user_t> for BprmCheckSecurityEventUser {
    fn from(e: ffi::bprm_check_security_event_user_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event.effective = Some(e.effective.into()).into();
        event
    }
}

impl From<ffi::bprm_check_security_event_t> for BprmCheckSecurityEvent {
    fn from(e: ffi::bprm_check_security_event_t) -> Self {
        let mut event = Self::default();
        event.set_timestamp(e.__timestamp);
        event.event = Some(e.event.into()).into();
        event.host = Some(Default::default()).into();
        event.process = Some(e.process.into()).into();
        event.user = Some(e.user.into()).into();
        event
    }
}

impl SerializableEvent for BprmCheckSecurityEvent {
    fn to_json(&self) -> SerializableResult<String> {
        match print_to_string(self) {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Json(e)),
        }
    }

    fn to_bytes(&self) -> SerializableResult<Vec<u8>> {
        let mut event = Event::new();
        event.bprm_check_security_event_t = Some(self.clone()).into();
        event.set_event_type(event::EventType::BPRMCHECKSECURITYEVENT);
        match event.write_to_bytes() {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Bytes(e)),
        }
    }

    fn update_id(&mut self, id: &mut str) {
        self.event.as_mut().and_then(|e| {
            e.set_id(id.to_string().to_owned());
            Some(e)
        });
    }

    fn update_sequence(&mut self, seq: u64) {
        self.event.as_mut().and_then(|e| {
            e.set_sequence(seq);
            Some(e)
        });
    }

    fn suffix(&self) -> &'static str {
        "bprm_check_security"
    }

    fn enrich_common<'a>(&'a mut self) -> SerializableResult<&'a mut Self> {
        {
            let cache = super::USERS_CACHE.lock().unwrap();
            // real enrichments
            let user = self.user.get_mut_ref();
            let uid = user.get_id().parse::<u32>().unwrap();
            let group = user.group.get_mut_ref();
            let gid = group.get_id().parse::<u32>().unwrap();

            for enriched_group in cache.get_group_by_gid(gid) {
                group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(uid) {
                user.set_name(enriched_user.name().to_string_lossy().to_string());
            }

            // effective enrichments
            let effective_user = user.effective.get_mut_ref();
            let effective_uid = effective_user.get_id().parse::<u32>().unwrap();
            let effective_group = effective_user.group.get_mut_ref();
            let effective_gid = effective_group.get_id().parse::<u32>().unwrap();
            for enriched_group in cache.get_group_by_gid(effective_gid) {
                effective_group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(effective_uid) {
                effective_user.set_name(enriched_user.name().to_string_lossy().to_string());
            }
        }

        // entity id enrichments
        let machine_id = machine_uid::get().unwrap(); // this should probably be error checked

        let process = self.process.get_mut_ref();
        let pid = process.get_pid();
        let process_start = process.get_start();
        let process_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", pid, 5),
            process_start
        );
        process.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(process_entity_id.as_bytes())
        ));

        let parent = process.parent.get_mut_ref();
        let ppid = parent.get_pid();
        let parent_start = parent.get_start();
        let parent_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", ppid, 5),
            parent_start
        );
        parent.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(parent_entity_id.as_bytes())
        ));

        let system = System::new();
        let host = self.host.get_mut_ref();
        host.set_uptime(system.get_uptime());
        for hostname in system.get_host_name() {
            host.set_hostname(hostname);
        }
        let all_interfaces = interfaces();
        let active_interfaces = all_interfaces
            .iter()
            .filter(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
        for interface in active_interfaces {
            if interface.mac.is_some() {
                host.mac.push(interface.mac.unwrap().to_string());
            }
            for ip in &interface.ips {
                host.ip.push(ip.ip().to_string());
            }
        }
        host.os = Some(Default::default()).into();

        let os = host.os.get_mut_ref();
        os.set_field_type("linux".to_string());
        for os_name in system.get_name() {
            os.set_name(os_name);
        }
        for kernel_version in system.get_kernel_version() {
            os.set_kernel(kernel_version);
        }

        Ok(self)
    }
}
impl From<ffi::path_rename_event_event_t> for PathRenameEventEvent {
    fn from(e: ffi::path_rename_event_event_t) -> Self {
        let mut event = Self::default();
        event.set_action(transform_string(e.action.into()));
        event
    }
}

impl From<ffi::path_rename_event_process_parent_t> for PathRenameEventProcessParent {
    fn from(e: ffi::path_rename_event_process_parent_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_args_count(e.args_count);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.set_ppid(e.ppid);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.set_executable(transform_string(e.executable.into()));
        event
    }
}

impl From<ffi::path_rename_event_process_t> for PathRenameEventProcess {
    fn from(e: ffi::path_rename_event_process_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_ppid(e.ppid);
        event.set_executable(transform_string(e.executable.into()));
        event.set_args_count(e.args_count);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.parent = Some(e.parent.into()).into();
        event
    }
}

impl From<ffi::path_rename_event_user_group_t> for PathRenameEventUserGroup {
    fn from(e: ffi::path_rename_event_user_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::path_rename_event_user_effective_group_t> for PathRenameEventUserEffectiveGroup {
    fn from(e: ffi::path_rename_event_user_effective_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::path_rename_event_user_effective_t> for PathRenameEventUserEffective {
    fn from(e: ffi::path_rename_event_user_effective_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event
    }
}

impl From<ffi::path_rename_event_user_t> for PathRenameEventUser {
    fn from(e: ffi::path_rename_event_user_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event.effective = Some(e.effective.into()).into();
        event
    }
}

impl From<ffi::path_rename_event_t> for PathRenameEvent {
    fn from(e: ffi::path_rename_event_t) -> Self {
        let mut event = Self::default();
        event.set_timestamp(e.__timestamp);
        event.event = Some(e.event.into()).into();
        event.host = Some(Default::default()).into();
        event.process = Some(e.process.into()).into();
        event.user = Some(e.user.into()).into();
        event
    }
}

impl SerializableEvent for PathRenameEvent {
    fn to_json(&self) -> SerializableResult<String> {
        match print_to_string(self) {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Json(e)),
        }
    }

    fn to_bytes(&self) -> SerializableResult<Vec<u8>> {
        let mut event = Event::new();
        event.path_rename_event_t = Some(self.clone()).into();
        event.set_event_type(event::EventType::PATHRENAMEEVENT);
        match event.write_to_bytes() {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Bytes(e)),
        }
    }

    fn update_id(&mut self, id: &mut str) {
        self.event.as_mut().and_then(|e| {
            e.set_id(id.to_string().to_owned());
            Some(e)
        });
    }

    fn update_sequence(&mut self, seq: u64) {
        self.event.as_mut().and_then(|e| {
            e.set_sequence(seq);
            Some(e)
        });
    }

    fn suffix(&self) -> &'static str {
        "path_rename"
    }

    fn enrich_common<'a>(&'a mut self) -> SerializableResult<&'a mut Self> {
        {
            let cache = super::USERS_CACHE.lock().unwrap();
            // real enrichments
            let user = self.user.get_mut_ref();
            let uid = user.get_id().parse::<u32>().unwrap();
            let group = user.group.get_mut_ref();
            let gid = group.get_id().parse::<u32>().unwrap();

            for enriched_group in cache.get_group_by_gid(gid) {
                group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(uid) {
                user.set_name(enriched_user.name().to_string_lossy().to_string());
            }

            // effective enrichments
            let effective_user = user.effective.get_mut_ref();
            let effective_uid = effective_user.get_id().parse::<u32>().unwrap();
            let effective_group = effective_user.group.get_mut_ref();
            let effective_gid = effective_group.get_id().parse::<u32>().unwrap();
            for enriched_group in cache.get_group_by_gid(effective_gid) {
                effective_group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(effective_uid) {
                effective_user.set_name(enriched_user.name().to_string_lossy().to_string());
            }
        }

        // entity id enrichments
        let machine_id = machine_uid::get().unwrap(); // this should probably be error checked

        let process = self.process.get_mut_ref();
        let pid = process.get_pid();
        let process_start = process.get_start();
        let process_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", pid, 5),
            process_start
        );
        process.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(process_entity_id.as_bytes())
        ));

        let parent = process.parent.get_mut_ref();
        let ppid = parent.get_pid();
        let parent_start = parent.get_start();
        let parent_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", ppid, 5),
            parent_start
        );
        parent.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(parent_entity_id.as_bytes())
        ));

        let system = System::new();
        let host = self.host.get_mut_ref();
        host.set_uptime(system.get_uptime());
        for hostname in system.get_host_name() {
            host.set_hostname(hostname);
        }
        let all_interfaces = interfaces();
        let active_interfaces = all_interfaces
            .iter()
            .filter(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
        for interface in active_interfaces {
            if interface.mac.is_some() {
                host.mac.push(interface.mac.unwrap().to_string());
            }
            for ip in &interface.ips {
                host.ip.push(ip.ip().to_string());
            }
        }
        host.os = Some(Default::default()).into();

        let os = host.os.get_mut_ref();
        os.set_field_type("linux".to_string());
        for os_name in system.get_name() {
            os.set_name(os_name);
        }
        for kernel_version in system.get_kernel_version() {
            os.set_kernel(kernel_version);
        }

        Ok(self)
    }
}
impl From<ffi::path_unlink_event_event_t> for PathUnlinkEventEvent {
    fn from(e: ffi::path_unlink_event_event_t) -> Self {
        let mut event = Self::default();
        event.set_action(transform_string(e.action.into()));
        event
    }
}

impl From<ffi::path_unlink_event_process_parent_t> for PathUnlinkEventProcessParent {
    fn from(e: ffi::path_unlink_event_process_parent_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_args_count(e.args_count);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.set_ppid(e.ppid);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.set_executable(transform_string(e.executable.into()));
        event
    }
}

impl From<ffi::path_unlink_event_process_t> for PathUnlinkEventProcess {
    fn from(e: ffi::path_unlink_event_process_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_ppid(e.ppid);
        event.set_executable(transform_string(e.executable.into()));
        event.set_args_count(e.args_count);
        event.set_start(e.start);
        event.set_thread_id(e.thread__id);
        event.args.append(&mut convert_string_array(event.get_args_count(), e.args.into()));
        event.parent = Some(e.parent.into()).into();
        event
    }
}

impl From<ffi::path_unlink_event_user_group_t> for PathUnlinkEventUserGroup {
    fn from(e: ffi::path_unlink_event_user_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::path_unlink_event_user_effective_group_t> for PathUnlinkEventUserEffectiveGroup {
    fn from(e: ffi::path_unlink_event_user_effective_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::path_unlink_event_user_effective_t> for PathUnlinkEventUserEffective {
    fn from(e: ffi::path_unlink_event_user_effective_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event
    }
}

impl From<ffi::path_unlink_event_user_t> for PathUnlinkEventUser {
    fn from(e: ffi::path_unlink_event_user_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event.effective = Some(e.effective.into()).into();
        event
    }
}

impl From<ffi::path_unlink_event_t> for PathUnlinkEvent {
    fn from(e: ffi::path_unlink_event_t) -> Self {
        let mut event = Self::default();
        event.set_timestamp(e.__timestamp);
        event.event = Some(e.event.into()).into();
        event.host = Some(Default::default()).into();
        event.process = Some(e.process.into()).into();
        event.user = Some(e.user.into()).into();
        event
    }
}

impl SerializableEvent for PathUnlinkEvent {
    fn to_json(&self) -> SerializableResult<String> {
        match print_to_string(self) {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Json(e)),
        }
    }

    fn to_bytes(&self) -> SerializableResult<Vec<u8>> {
        let mut event = Event::new();
        event.path_unlink_event_t = Some(self.clone()).into();
        event.set_event_type(event::EventType::PATHUNLINKEVENT);
        match event.write_to_bytes() {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Bytes(e)),
        }
    }

    fn update_id(&mut self, id: &mut str) {
        self.event.as_mut().and_then(|e| {
            e.set_id(id.to_string().to_owned());
            Some(e)
        });
    }

    fn update_sequence(&mut self, seq: u64) {
        self.event.as_mut().and_then(|e| {
            e.set_sequence(seq);
            Some(e)
        });
    }

    fn suffix(&self) -> &'static str {
        "path_unlink"
    }

    fn enrich_common<'a>(&'a mut self) -> SerializableResult<&'a mut Self> {
        {
            let cache = super::USERS_CACHE.lock().unwrap();
            // real enrichments
            let user = self.user.get_mut_ref();
            let uid = user.get_id().parse::<u32>().unwrap();
            let group = user.group.get_mut_ref();
            let gid = group.get_id().parse::<u32>().unwrap();

            for enriched_group in cache.get_group_by_gid(gid) {
                group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(uid) {
                user.set_name(enriched_user.name().to_string_lossy().to_string());
            }

            // effective enrichments
            let effective_user = user.effective.get_mut_ref();
            let effective_uid = effective_user.get_id().parse::<u32>().unwrap();
            let effective_group = effective_user.group.get_mut_ref();
            let effective_gid = effective_group.get_id().parse::<u32>().unwrap();
            for enriched_group in cache.get_group_by_gid(effective_gid) {
                effective_group.set_name(enriched_group.name().to_string_lossy().to_string());
            }
            for enriched_user in cache.get_user_by_uid(effective_uid) {
                effective_user.set_name(enriched_user.name().to_string_lossy().to_string());
            }
        }

        // entity id enrichments
        let machine_id = machine_uid::get().unwrap(); // this should probably be error checked

        let process = self.process.get_mut_ref();
        let pid = process.get_pid();
        let process_start = process.get_start();
        let process_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", pid, 5),
            process_start
        );
        process.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(process_entity_id.as_bytes())
        ));

        let parent = process.parent.get_mut_ref();
        let ppid = parent.get_pid();
        let parent_start = parent.get_start();
        let parent_entity_id = format!(
            "{}{}{}",
            machine_id,
            format!("{:01$}", ppid, 5),
            parent_start
        );
        parent.set_entity_id(format!(
            "{:x}",
            sha2::Sha256::digest(parent_entity_id.as_bytes())
        ));

        let system = System::new();
        let host = self.host.get_mut_ref();
        host.set_uptime(system.get_uptime());
        for hostname in system.get_host_name() {
            host.set_hostname(hostname);
        }
        let all_interfaces = interfaces();
        let active_interfaces = all_interfaces
            .iter()
            .filter(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
        for interface in active_interfaces {
            if interface.mac.is_some() {
                host.mac.push(interface.mac.unwrap().to_string());
            }
            for ip in &interface.ips {
                host.ip.push(ip.ip().to_string());
            }
        }
        host.os = Some(Default::default()).into();

        let os = host.os.get_mut_ref();
        os.set_field_type("linux".to_string());
        for os_name in system.get_name() {
            os.set_name(os_name);
        }
        for kernel_version in system.get_kernel_version() {
            os.set_kernel(kernel_version);
        }

        Ok(self)
    }
}
