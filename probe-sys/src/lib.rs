#![allow(non_camel_case_types)]

use std::fmt;
use std::os::raw::c_int;
use std::panic;

pub mod ffi {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct event {
        pub tid: u32,
        pub pid: u32,
        pub ppid: u32,
        pub gid: u32,
        pub uid: u32,
        pub state: u8,
        pub program: [c_char; 256],
        pub filename: [c_char; 256],
    }
    pub type event_handler = extern "C" fn(ctx: *mut c_void, e: event);
    pub enum state {}
    extern "C" {
        pub fn new_state(
            ctx: *mut c_void,
            handler: event_handler,
            filtered_uid: c_uint,
        ) -> *mut state;
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
    pub unsafe fn unpack_closure<F>(closure: &mut F) -> (*mut c_void, event_handler)
    where
        F: FnMut(event),
    {
        extern "C" fn trampoline<F>(data: *mut c_void, e: event)
        where
            F: FnMut(event),
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

#[derive(PartialEq, PartialOrd, Debug, Clone)]
pub enum ExecState {
    Allowed,
    Denied,
    Unknown,
}

impl From<u8> for ExecState {
    fn from(value: u8) -> Self {
        match value {
            0u8 => return ExecState::Allowed,
            1u8 => return ExecState::Denied,
            _ => return ExecState::Unknown,
        };
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub tid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub gid: u32,
    pub uid: u32,
    pub state: ExecState,
    pub filename: String,
    pub program: String,
}

pub struct Probe<'a> {
    ctx: Option<*mut ffi::state>,
    // store the closure so that we make sure it has
    // the same lifetime as the state wrapper
    _handler: Option<Box<dyn 'a + Fn(ffi::event)>>,
    filtered_uid: u32,
}

use std::ffi::CStr;
impl<'a> Probe<'a> {
    pub fn filter(uid: u32) -> Self {
        Self {
            ctx: None,
            _handler: None,
            filtered_uid: uid,
        }
    }

    pub fn run<F: 'a>(&mut self, handler: F) -> Result<&mut Self, Error>
    where
        F: 'a + Fn(Event) + panic::RefUnwindSafe,
    {
        let mut wrapper = move |e: ffi::event| {
            let result = panic::catch_unwind(|| unsafe {
                handler(Event {
                    tid: e.tid,
                    pid: e.pid,
                    ppid: e.ppid,
                    gid: e.gid,
                    uid: e.uid,
                    state: e.state.into(),
                    filename: CStr::from_ptr(e.filename.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                    program: CStr::from_ptr(e.program.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                });
            });
            // do something with the panic
            result.unwrap();
        };
        let (closure, callback) = unsafe { ffi::unpack_closure(&mut wrapper) };
        let state = unsafe { ffi::new_state(closure, callback, self.filtered_uid) };
        if state.is_null() {
            return Err(Error::InitializationError);
        }
        self.ctx = Some(state);
        self._handler = Some(Box::new(wrapper));
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
