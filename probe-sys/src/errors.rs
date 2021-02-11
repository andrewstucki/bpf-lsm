use protobuf::json::PrintError;
use protobuf::{ProtobufError, Message};
use std::{error, fmt};

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

#[derive(Debug)]
pub enum SerializationError {
    Json(PrintError),
    Bytes(ProtobufError),
    Transform(String),
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
          Self::Json(_e) => write!(f, "json serialization failed"),
          Self::Bytes(e) => std::fmt::Display::fmt(&e, f),
          Self::Transform(e) => std::fmt::Display::fmt(&e, f),
        }
    }
}

impl error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
          Self::Json(_) => None,
          Self::Bytes(e) => Some(e),
          Self::Transform(_) => None,
        }
    }
}

pub type SerializableResult<T> = Result<T, SerializationError>;
