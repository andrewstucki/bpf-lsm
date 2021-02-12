use log::{debug, warn};
use rule_compiler::{compile, Operation};
use std::convert::TryInto;
use std::mem::transmute_copy;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::panic;
use std::path::Path;
use sysinfo::{ProcessExt, System, SystemExt};

use crate::errors::Error;
use crate::ffi_generated as ffi;
use crate::query_writer::BpfQueryWriterFactory;
use crate::struct_pb;
use crate::traits::{ProbeHandler, QueryStruct};

pub struct Probe<'a> {
    ctx: Option<*mut ffi::state>,
    // store the closures so that we make sure it has
    // the same lifetime as the state wrapper
    _bprm_check_security_handler: Option<Box<dyn 'a + Fn(ffi::bprm_check_security_event_t)>>,
    _inode_unlink_handler: Option<Box<dyn 'a + Fn(ffi::inode_unlink_event_t)>>,
    debug: bool,
}

impl<'a> Probe<'a> {
    pub fn new() -> Self {
        Self {
            ctx: None,
            _bprm_check_security_handler: None,
            _inode_unlink_handler: None,
            debug: false,
        }
    }

    pub fn apply(&mut self, rules: Vec<&str>) -> Result<(), String> {
        for rule in &rules {
            let compiled = compile(rule)?;
            let query_writer = &BpfQueryWriterFactory::new(self);
            compiled.encode(query_writer)?
        }
        Ok(())
    }

    pub fn debug(&mut self, debug: bool) -> &mut Self {
        self.debug = debug;
        self
    }

    pub fn run<F: 'a, U>(&mut self, handler: F) -> Result<&mut Self, Error>
    where
        F: 'a + ProbeHandler<U> + panic::RefUnwindSafe + Copy,
        U: std::fmt::Display,
    {
        let mut bprm_check_security_wrapper = move |e: ffi::bprm_check_security_event_t| {
            let result = panic::catch_unwind(|| {
                handler
                    .enqueue(&mut struct_pb::BprmCheckSecurityEvent::from(e))
                    .unwrap_or_else(|e| warn!("error enqueuing data: {}", e));
            });
            if result.is_err() {
                debug!("panic while handling event");
            }
        };
        let (bprm_check_security_closure, bprm_check_security_callback) =
            unsafe { ffi::unpack_bprm_check_security_closure(&mut bprm_check_security_wrapper) };
        let mut inode_unlink_wrapper = move |e: ffi::inode_unlink_event_t| {
            let result = panic::catch_unwind(|| {
                handler
                    .enqueue(&mut struct_pb::InodeUnlinkEvent::from(e))
                    .unwrap_or_else(|e| warn!("error enqueuing data: {}", e));
            });
            if result.is_err() {
                debug!("panic while handling event");
            }
        };
        let (inode_unlink_closure, inode_unlink_callback) =
            unsafe { ffi::unpack_inode_unlink_closure(&mut inode_unlink_wrapper) };
        let state_config = ffi::state_configuration {
            debug: self.debug,
            bprm_check_security_ctx: bprm_check_security_closure,
            bprm_check_security_handler: bprm_check_security_callback,
            inode_unlink_ctx: inode_unlink_closure,
            inode_unlink_handler: inode_unlink_callback,
        };
        let state = unsafe { ffi::new_state(state_config) };
        if state.is_null() {
            return Err(Error::InitializationError);
        }
        let mut system = System::new();
        system.refresh_processes();
        let empty_path = Path::new("");
        for (pid, process) in system.get_processes() {
            let exe = process.exe();
            if exe == empty_path {
                continue;
            }
            let name = process.name();
            let cmd = process.cmd();
            let mut cached: ffi::cached_process = Default::default();
            for (dest, src) in cached.executable.iter_mut().zip(exe.as_os_str().as_bytes().iter()) {
                *dest = *src as _;
            }
            for (dest, src) in cached.name.iter_mut().zip(name.as_bytes().iter()) {
                *dest = *src as _;
            }
            for (index, c) in cached.args.iter_mut().enumerate() {
                if cmd.len() > index {
                    for (dest, src) in c.iter_mut().zip(cmd[index].as_bytes().iter()) {
                        *dest = *src as _;
                    }
                    cached.args_count += 1;
                }
            }

            if cached.args_count < cmd.len().try_into().unwrap() {
                cached.truncated = 1;
            }
            unsafe { ffi::cache_process(state, *pid as i32, &cached) };
        }
        self.ctx = Some(state);
        self._bprm_check_security_handler = Some(Box::new(bprm_check_security_wrapper));
        self._inode_unlink_handler = Some(Box::new(inode_unlink_wrapper));
        Ok(self)
    }

    pub fn apply_rule<T: QueryStruct>(&self, module: String, operation: Operation, rule: T) {
        match self.ctx {
            Some(ctx) => match (module.as_str(), operation) {
                ("bprm_check_security", Operation::Filter) => unsafe {
                    ffi::flush_bprm_check_security_filter_rule(ctx, transmute_copy(&rule));
                },
                ("bprm_check_security", Operation::Reject) => unsafe {
                    let rule = transmute_copy(&rule);
                    ffi::flush_bprm_check_security_rejection_rule(ctx, rule);
                },
                ("inode_unlink", Operation::Filter) => unsafe {
                    ffi::flush_inode_unlink_filter_rule(ctx, transmute_copy(&rule));
                },
                ("inode_unlink", Operation::Reject) => unsafe {
                    let rule = transmute_copy(&rule);
                    ffi::flush_inode_unlink_rejection_rule(ctx, rule);
                },
                _ => return,
            },
            _ => return,
        }
    }

    pub fn poll(&self, timeout: i32) {
        match self.ctx {
            Some(ctx) => unsafe { ffi::poll_state(ctx, timeout as c_int) },
            _ => return,
        }
    }
}

impl<'a> Drop for Probe<'a> {
    fn drop(&mut self) {
        match self.ctx {
            Some(ctx) => unsafe { ffi::destroy_state(ctx) },
            _ => return,
        }
    }
}