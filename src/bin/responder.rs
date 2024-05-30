//! Agent Responder
//!
//! This executable takes informations about the current authentication session and calls
//! [`AuthenticationAgentResponse2()`][auth-response] after elevating itself as root.
//!
//! The session informations are piped throught stdin, in that order, each on it's own line
//! (separated by `\n`):
//! - Agent UID
//! - Session Cookie
//! - Identity kind
//! - Identity key
//! - identity value
//!
//! [auth-response]: https://docs.rs/zbus_polkit/latest/zbus_polkit/policykit1/struct.AuthorityProxy.html#method.authentication_agent_response2

use std::{
    collections::HashMap,
    io::{stdin, Read},
};

use log::{debug, error, trace};
use nix::libc::{exit, setuid};
use zbus::Connection;
use zbus_polkit::policykit1::{AuthorityProxy, Identity};

fn main() -> anyhow::Result<()> {
    pkatt::setup_logging();

    let mut stdin = stdin();
    let mut buf = String::new();
    let _ = stdin.read_to_string(&mut buf);

    let mut data = buf.split("\n");

    trace!("parsing input data");
    let agent_uid: u32 = data.next().unwrap().parse()?;
    let cookie = data.next().unwrap();
    let kind = data.next().unwrap();
    let key = data.next().unwrap();
    let id: u32 = data.next().unwrap().parse()?;

    let mut details = HashMap::new();
    details.insert(key, id.into());

    let identity = Identity {
        identity_kind: &kind,
        identity_details: &details,
    };

    trace!("using setuid");
    unsafe {
        if setuid(0) != 0 {
            error!("Unable to elevate privileges, is the setuid flag correclty set ?");
            exit(1);
        };
    }

    debug!("Authenticating with agent uid: {agent_uid}, cookie: {cookie:?}, identity kind: {kind:?}, identity: {key:?} => {id}");

    smol::block_on(async {
        let conn = Connection::system().await?;
        let proxy = AuthorityProxy::new(&conn).await?;

        proxy
            .authentication_agent_response2(agent_uid, &cookie, &identity)
            .await?;

        Ok(())
    })
}
