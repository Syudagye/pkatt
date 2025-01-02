use std::{
    io::{self, stdout},
    process::{Command, ExitStatus, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{identity::Identity, Session};

/// Data passed to the prompt program
#[derive(Debug, Serialize, Deserialize)]
pub struct PromptInput {
    /// Message to diplay in the prompt
    pub message: String,
    /// Users which can authenticate for this session
    pub users: Vec<Identity>,
}

/// Information returned by a prompt
#[derive(Debug, Serialize, Deserialize)]
pub struct PromptResponse {
    /// uid or gid of the identity which authenticated
    pub id: u32,
    /// The password to check in plain text
    pub password: String,
}

/// Dummy authentication methods, which does not prompt for password and just authenticate to
/// polkit using the responder
pub fn authenticate(session: &Session, uid: u32) -> io::Result<ExitStatus> {
    let mut responder = Command::new("target/debug/pkatt-responder")
        .stdin(Stdio::piped())
        .stdout(stdout())
        .spawn()
        .expect("ay");

    let data = session.create_responder_input(uid).unwrap();

    let _ = {
        let respin = responder.stdin.take().unwrap();
        serde_json::to_writer(respin, &data)?;
    };

    responder.wait()
}
