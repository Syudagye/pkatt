//! Agent Responder
//!
//! This executable takes informations about the current authentication session and calls
//! [`AuthenticationAgentResponse2()`][auth-response] after elevating itself as root.
//!
//! This executable requires the setuid permission and should be owned by root
//!
//! [auth-response]: https://docs.rs/zbus_polkit/latest/zbus_polkit/policykit1/struct.AuthorityProxy.html#method.authentication_agent_response2

use std::io::stdin;

use log::{debug, error, trace};
use nix::libc::{exit, setuid};
use pkatt_agent::{identity::IdentityContext, ResponderInput};
use zbus::Connection;
use zbus_polkit::policykit1::AuthorityProxy;

fn main() -> anyhow::Result<()> {
    pkatt_agent::setup_logging();

    let stdin = stdin();

    let data: ResponderInput = serde_json::from_reader(stdin)?;
    let mut ctx = IdentityContext::default();
    let identity = data.identity.create_identity(&mut ctx);

    trace!("using setuid");
    unsafe {
        if setuid(0) != 0 {
            error!("Unable to elevate privileges, is the setuid flag correclty set ?");
            exit(1);
        };
    }

    debug!(
        "Authenticating with agent uid: {}, cookie: {}, identity: {:?}",
        data.agent_uid, data.cookie, data.identity
    );

    smol::block_on(async {
        let conn = Connection::system().await?;
        let proxy = AuthorityProxy::new(&conn).await?;

        proxy
            .authentication_agent_response2(data.agent_uid, &data.cookie, &identity)
            .await?;

        Ok(())
    })
}
