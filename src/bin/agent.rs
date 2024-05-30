use std::{
    collections::HashMap,
    io::{stdout, Write},
    process::{Command, Stdio},
};

use log::{debug, info};
use pkatt::{prompt::authenticate, Identity, OwnedIdentity, Session};
use smol::stream::{pending, StreamExt};
use zbus::{
    interface,
    zvariant::{OwnedValue, Str},
    Connection,
};
use zbus_polkit::policykit1::{AuthorityProxy, Subject};

struct Agent {
    sessions: HashMap<String, Session>,
}

impl Agent {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

#[interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Agent {
    /// BeginAuthentication method
    async fn begin_authentication(
        &mut self,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<&str, &str>,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> zbus::fdo::Result<()> {
        debug!("Authentication asked !");
        debug!("action_id: {action_id}, message: {message}, icon_name: {icon_name}, details: {details:?}, cookie: {cookie}, identities: {identities:?}");

        let identities = identities
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<OwnedIdentity>, <OwnedIdentity as TryFrom<Identity<'_>>>::Error>>(
            )
            .unwrap();
        let session = Session {
            action_id: action_id.to_string(),
            message: message.to_string(),
            icon_name: icon_name.to_string(),
            cookie: cookie.to_string(),
            identities,
            selected_identity_index: 0,
        };
        let out = authenticate(&session);

        info!("Responder exit code: {}", out.unwrap());

        self.sessions.insert(String::from(cookie), session);
        Ok(())
    }

    /// CancelAuthentication method
    async fn cancel_authentication(&self, cookie: &str) -> zbus::fdo::Result<()> {
        debug!("Authentication cancled ! {cookie}");
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    pkatt::setup_logging();

    smol::block_on(async {
        let conn = Connection::system().await?;

        // register agent
        let agent = Agent::new();
        const OBJ_PATH: &str = "/ovh/syu/polkitAgent";
        conn.object_server().at(OBJ_PATH, agent).await?;

        // connect to authority
        let proxy = AuthorityProxy::new(&conn).await?;
        let session_id = std::env::var("XDG_SESSION_ID")?;

        let mut details = HashMap::new();
        let val: OwnedValue = {
            let wrapped: Str<'_> = session_id.into();
            wrapped.into()
        };
        details.insert("session-id".to_string(), val);

        let sub = Subject {
            subject_kind: "unix-session".to_string(),
            subject_details: details,
        };
        proxy
            .register_authentication_agent(&sub, "en_US.UTF-8", OBJ_PATH)
            .await?;

        pending::<()>().next().await;

        Ok(())
    })
}
