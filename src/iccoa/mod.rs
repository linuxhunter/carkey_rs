#![recursion_limit = "1024"]

use error_chain::error_chain;

mod objects;
mod pairing;
mod auth;
mod command;

mod errors {
    use super::*;

    error_chain! {
        foreign_links {
            Io(std::io::Error);
        }
        errors {
            ICCOAObjectError(t: String)
            ICCOAPairingError(t: String)
            ICCOAAuthError(t: String)
            ICCOACommandError(t: String)
        }
    }
}