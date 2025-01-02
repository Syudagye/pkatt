//! Agent Responder
//!
//! This executable takes informations about the current authentication session and calls
//! [`AuthenticationAgentResponse2()`][auth-response] after elevating itself as root.
//!
//! This executable requires the setuid permission and should be owned by root
//!
//! [auth-response]: https://docs.rs/zbus_polkit/latest/zbus_polkit/policykit1/struct.AuthorityProxy.html#method.authentication_agent_response2

use std::{collections::HashMap, io::stdin};

use log::{debug, error, trace};
use nix::libc::{exit, setuid};
use pkatt::{Identity, ResponderInput};
use zbus::Connection;
use zbus_polkit::policykit1::AuthorityProxy;

fn main() -> anyhow::Result<()> {
    let stdin = stdin();

    let data: ResponderInput = serde_json::from_reader(stdin)?;
    let mut ctx = IdentityContext::default();
    let identity = ctx.create_identity(&data.identity);

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

/// Context from creating a [`zbus_polkit::policykit1::Identity`] from a [`pkatt::identity::Identity`]
#[derive(Default)]
pub struct IdentityContext<'v>(HashMap<&'v str, zbus::zvariant::Value<'v>>);

impl<'v> IdentityContext<'v> {
    /// Convert into a [`zbus_polkit::policykit1::Identity`]
    pub fn create_identity(
        &'v mut self,
        identity: &'v Identity,
    ) -> zbus_polkit::policykit1::Identity<'v> {
        match identity {
            Identity::User { uid, .. } => {
                self.0.insert("uid", uid.into());
                zbus_polkit::policykit1::Identity {
                    identity_kind: "unix-user",
                    identity_details: &self.0,
                }
            }
            Identity::Group { gid, .. } => {
                self.0.insert("gid", gid.into());
                zbus_polkit::policykit1::Identity {
                    identity_kind: "unix-group",
                    identity_details: &self.0,
                }
            }
        }
    }
}
