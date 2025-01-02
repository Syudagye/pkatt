use std::{collections::HashMap, sync::Arc};

use log::error;
use pkatt_agent::Agent;
use smol::stream::{pending, StreamExt};
use zbus::{
    zvariant::{OwnedValue, Str},
    Connection,
};
use zbus_polkit::policykit1::{AuthorityProxy, Subject};

fn main() -> anyhow::Result<()> {
    color_eyre::install().unwrap_or_else(|_| {
        eprintln!("Unable to setup fancy panic messages, falling back to default panic format")
    });
    env_logger::init();

    let promp_path = match std::env::args().skip(1).next() {
        Some(path) => path,
        None => {
            error!("Missing path for the prompt executable");
            std::process::exit(1);
        }
    };

    smol::block_on(async {
        let conn = Connection::system().await?;

        // register agent
        let agent = Agent::new(promp_path);
        const OBJ_PATH: &str = "/ovh/syu/polkitAgent";
        conn.object_server().at(OBJ_PATH, agent).await?;

        // connect to authority
        let proxy = Arc::new(AuthorityProxy::new(&conn).await?);
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
