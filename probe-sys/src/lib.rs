#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use std::fmt;
use std::os::raw::c_int;
use std::panic;

pub mod ffi {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    // begin bprm_check_security

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_process_target_t {
        pub executable: [c_char; 256],
        pub args_count: u64,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_process_t {
        pub pid: u32,
        pub entity_id: [c_char; 256],
        pub name: [c_char; 256],
        pub ppid: u32,
        pub thread__id: u64,
        pub target: bprm_check_security_event_process_target_t,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_user_group_t {
        pub id: u32,
        pub name: [c_char; 256],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_user_t {
        pub id: u32,
        pub name: [c_char; 256],
        pub group: bprm_check_security_event_user_group_t,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_t {
        pub __timestamp: u64,
        pub process: bprm_check_security_event_process_t,
        pub user: bprm_check_security_event_user_t,
    }

    pub type bprm_check_security_event_handler =
        extern "C" fn(ctx: *mut c_void, e: bprm_check_security_event_t);

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct state_configuration {
        pub filtered_uid: u32,
        pub debug: bool,
        pub bprm_check_security_ctx: *mut c_void,
        pub bprm_check_security_handler: bprm_check_security_event_handler,
    }
    pub enum state {}
    extern "C" {
        pub fn new_state(config: state_configuration) -> *mut state;
        pub fn poll_state(_self: *mut state, timeout: c_int);
        pub fn destroy_state(_self: *mut state);
    }

    /// Unpack a Rust closure, extracting a `void*` pointer to the data and a
    /// trampoline function which can be used to invoke it.
    ///
    /// # Safety
    ///
    /// It is the user's responsibility to ensure the closure outlives the returned
    /// `void*` pointer.
    ///
    /// Calling the trampoline function with anything except the `void*` pointer
    /// will result in *Undefined Behaviour*.
    ///
    /// The closure should guarantee that it never panics, seeing as panicking
    /// across the FFI barrier is *Undefined Behaviour*. You may find
    /// `std::panic::catch_unwind()` useful.

    pub unsafe fn unpack_bprm_check_security_closure<F>(
        closure: &mut F,
    ) -> (*mut c_void, bprm_check_security_event_handler)
    where
        F: FnMut(bprm_check_security_event_t),
    {
        extern "C" fn trampoline<F>(data: *mut c_void, e: bprm_check_security_event_t)
        where
            F: FnMut(bprm_check_security_event_t),
        {
            let closure: &mut F = unsafe { &mut *(data as *mut F) };
            (*closure)(e);
        }

        (closure as *mut F as *mut c_void, trampoline::<F>)
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InitializationError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InitializationError => f.write_str(
                "Could not initialize BPF object, ensure you're using Linux kernel >= 4.18",
            ),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Event {
    pub tid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub gid: u32,
    pub uid: u32,
    pub filename: String,
    pub program: String,
}

use std::ffi::CStr;
use std::os::raw::c_char;
fn transform_string(val: Vec<c_char>) -> String {
    unsafe { CStr::from_ptr(val.as_ptr()).to_string_lossy().into_owned() }
}

fn int_to_string(v: u32) -> String {
    v.to_string()
}

pub struct Probe<'a> {
    ctx: Option<*mut ffi::state>,
    // store the closures so that we make sure it has
    // the same lifetime as the state wrapper
    _bprm_check_security_handler: Option<Box<dyn 'a + Fn(ffi::bprm_check_security_event_t)>>,

    filtered_uid: u32,
    debug: bool,
}

#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEventEvent {
    id: String,

    code: String,

    kind: String,

    category: String,

    action: String,

    r#type: String,

    module: String,

    provider: String,

    sequence: u64,

    ingested: u64,
}
#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEventProcessTarget {
    executable: String,

    args_count: u64,
}
impl From<ffi::bprm_check_security_event_process_target_t> for BprmCheckSecurityEventProcessTarget {
    fn from(e: ffi::bprm_check_security_event_process_target_t) -> Self {
        let mut event = Self::default();
        event.executable = transform_string(e.executable.into());
        event.args_count = e.args_count;
        event
    }
}

#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEventProcess {
    pid: u32,

    entity_id: String,

    name: String,

    ppid: u32,

    thread_id: u64,

    target: BprmCheckSecurityEventProcessTarget,
}
impl From<ffi::bprm_check_security_event_process_t> for BprmCheckSecurityEventProcess {
    fn from(e: ffi::bprm_check_security_event_process_t) -> Self {
        let mut event = Self::default();
        event.pid = e.pid;
        event.entity_id = transform_string(e.entity_id.into());
        event.name = transform_string(e.name.into());
        event.ppid = e.ppid;
        event.thread_id = e.thread__id;
        event.target = e.target.into();
        event
    }
}

#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEventUserGroup {
    id: String,

    name: String,
}
impl From<ffi::bprm_check_security_event_user_group_t> for BprmCheckSecurityEventUserGroup {
    fn from(e: ffi::bprm_check_security_event_user_group_t) -> Self {
        let mut event = Self::default();
        event.id = int_to_string(e.id.into());
        event.name = transform_string(e.name.into());
        event
    }
}

#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEventUser {
    id: String,

    name: String,

    group: BprmCheckSecurityEventUserGroup,
}
impl From<ffi::bprm_check_security_event_user_t> for BprmCheckSecurityEventUser {
    fn from(e: ffi::bprm_check_security_event_user_t) -> Self {
        let mut event = Self::default();
        event.id = int_to_string(e.id.into());
        event.name = transform_string(e.name.into());
        event.group = e.group.into();
        event
    }
}

#[derive(Default, Debug, Clone)]
pub struct BprmCheckSecurityEvent {
    _timestamp: u64,

    event: BprmCheckSecurityEventEvent,

    process: BprmCheckSecurityEventProcess,

    user: BprmCheckSecurityEventUser,
}
impl From<ffi::bprm_check_security_event_t> for BprmCheckSecurityEvent {
    fn from(e: ffi::bprm_check_security_event_t) -> Self {
        let mut event = Self::default();
        event._timestamp = e.__timestamp;
        event.process = e.process.into();
        event.user = e.user.into();
        event
    }
}

pub trait ProbeHandler {
    fn handle_bprm_check_security(&self, e: BprmCheckSecurityEvent);
}

impl<'a> Probe<'a> {
    pub fn new() -> Self {
        Self {
            ctx: None,
            _bprm_check_security_handler: None,

            filtered_uid: std::u32::MAX,
            debug: false,
        }
    }

    pub fn filter(&mut self, uid: u32) -> &mut Self {
        self.filtered_uid = uid;
        self
    }

    pub fn debug(&mut self, debug: bool) -> &mut Self {
        self.debug = debug;
        self
    }

    pub fn run<F: 'a>(&mut self, handler: F) -> Result<&mut Self, Error>
    where
        F: 'a + ProbeHandler + panic::RefUnwindSafe,
    {
        let mut bprm_check_security_wrapper = move |e: ffi::bprm_check_security_event_t| {
            let result = panic::catch_unwind(|| handler.handle_bprm_check_security(e.into()));
            // do something with the panic
            result.unwrap();
        };
        let (bprm_check_security_closure, bprm_check_security_callback) =
            unsafe { ffi::unpack_bprm_check_security_closure(&mut bprm_check_security_wrapper) };

        let state_config = ffi::state_configuration {
            filtered_uid: self.filtered_uid,
            debug: self.debug,
            bprm_check_security_ctx: bprm_check_security_closure,
            bprm_check_security_handler: bprm_check_security_callback,
        };
        let state = unsafe { ffi::new_state(state_config) };
        if state.is_null() {
            return Err(Error::InitializationError);
        }
        self.ctx = Some(state);
        self._bprm_check_security_handler = Some(Box::new(bprm_check_security_wrapper));

        Ok(self)
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
