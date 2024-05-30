use std::{
    io::{self, stdout, Write},
    process::{Command, ExitStatus, Stdio},
};

use crate::Session;

/// Dummy authentication methods, which does not prompt for passwork and just authenticate to
/// polkit using the responder
pub fn authenticate(session: &Session) -> io::Result<ExitStatus> {
    let mut responder = Command::new("target/debug/pkatt-responder")
        .stdin(Stdio::piped())
        .stdout(stdout())
        .spawn()
        .expect("ay");

    let data = session.serialize_to_responder();

    let _ = {
        let mut respin = responder.stdin.take().unwrap();
        respin.write_all(&data)
    };

    responder.wait()
}
