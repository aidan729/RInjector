use std::fmt::{self};

const UNKNOWN_ERROR_MESSAGE: &'static str = "unknown error";

#[derive(Debug, Clone)]
pub struct Win32Error {
    pub code: u32,
    pub message: Option<String>,
}

#[allow(dead_code)]
impl Win32Error {
    pub fn new() -> Self {
        Self { code: 0, message: None }
    }
}

// marking Win32Error as `Sync` and `Send` safely
unsafe impl Sync for Win32Error {}
unsafe impl Send for Win32Error {}

// implementing Display for Win32Error
impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.message.as_ref() {
            Some(s) => write!(f, "{}: {}", self.code, s),
            None => write!(f, "{}: {}", self.code, UNKNOWN_ERROR_MESSAGE),
        }
    }
}
