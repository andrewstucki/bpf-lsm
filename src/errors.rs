#[derive(Debug)]
pub enum Error {
    EnqueuingError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::EnqueuingError(ref e) => write!(f, "could not enqueue data: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::EnqueuingError(..) => None,
        }
    }
}
