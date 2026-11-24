pub mod compute;
pub mod db;
pub mod economy;
pub mod iam;
pub mod js;
pub mod shell;
pub mod storage;
pub mod ux;

use nu_protocol::shell_error::generic::GenericError;
use nu_protocol::{ShellError, Span};
use std::borrow::Cow;

/// Shared helper to construct a `ShellError::Generic` across Nexus-IO modules.
pub fn shell_err(
    title: impl Into<Cow<'static, str>>,
    msg: impl Into<Cow<'static, str>>,
    span: Option<Span>,
    help: Option<Cow<'static, str>>,
) -> ShellError {
    let mut err = match span {
        Some(s) => GenericError::new(title, msg, s),
        None => GenericError::new_internal(title, msg),
    };
    if let Some(h) = help {
        err = err.with_help(h);
    }
    ShellError::Generic(err)
}
