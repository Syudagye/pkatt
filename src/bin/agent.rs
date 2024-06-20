use std::{
    collections::HashMap,
    io::{Read, Write},
    process::{Command, Stdio},
};

use log::{debug, error, info, trace};
use pam::Client;
use pkatt::{prompt::authenticate, Identity, Session};
use smol::{
    channel::Sender,
    pin,
    stream::{pending, StreamExt},
};
use zbus::{
    interface,
    zvariant::{OwnedValue, Str},
    Connection,
};
use zbus_polkit::policykit1::{AuthorityProxy, Subject};

struct Agent {
    session_cancel_signals: HashMap<String, Sender<()>>,
    promp_path: String,
}

impl Agent {
    pub fn new(promp_path: String) -> Self {
        Self {
            session_cancel_signals: HashMap::new(),
            promp_path,
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

        let session = Session::new(
            message.to_string(),
            icon_name.to_string(),
            cookie.to_string(),
            identities,
        );

        let (cancel_sender, cancel_receiver) = smol::channel::unbounded();
        pin!(cancel_receiver);
        self.session_cancel_signals
            .insert(session.cookie.clone(), cancel_sender);

        let users = session.serialize_users_to_prompt();
        let mut attempts = 3;

        loop {
            let mut promp_child = Command::new(&self.promp_path)
                .args([&session.message, &session.icon_name, &attempts.to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            debug!("Started promp {}", self.promp_path);

            let mut stdin = promp_child.stdin.take().unwrap();
            stdin.write(&users).unwrap();

            let res = smol::future::race(
                async {
                    let _ = cancel_receiver.next().await;
                    debug!("Received stop signal, stopping sesssion");
                    None
                },
                async {
                    let exit = promp_child.wait().unwrap();
                    Some(exit.code())
                },
            )
            .await;

            let mut stdout = promp_child.stdout.take().unwrap();
            let mut passwd = String::new();
            stdout.read_to_string(&mut passwd).unwrap();

            let Some((uid, passwd)) = passwd.split_once(":") else {
                error!("Malformed response from prompt");
                return Err(zbus::fdo::Error::AuthFailed(String::from(
                    "Prompt program returned malformed data",
                )));
            };

            let uid: u32 = match uid.parse() {
                Ok(u) => u,
                Err(e) => {
                    error!("Can't read uid returned by the prompt: {}", e);
                    attempts -= 1;
                    continue;
                }
            };

            trace!("{:?}", passwd);

            let Some(identity) = session.uid_identities.get(&uid) else {
                error!("Unable to find identity for uid {}", uid);
                return Err(zbus::fdo::Error::AuthFailed(String::from("unknown uid")));
            };

            // TODO: Check passord with PAM
            let mut auth =
                Client::with_password("system-auth").expect("Failed to init PAM client!");
            auth.conversation_mut().set_credentials("syu", passwd);

            let auth_resp = auth.authenticate();
            debug!("{:?}", auth_resp);

            if auth_resp.is_ok() {
                let out = authenticate(&session, uid);
                info!("Responder exit code: {}", out.unwrap());
                break;
            }

            attempts -= 1;
            if attempts == 0 {
                error!("All attempts failed, stopping session");
                return Err(zbus::fdo::Error::AccessDenied(String::from(
                    "All attempts failed",
                )));
            }

            error!("Authentication Failed, {} attempts remaining", attempts);
            continue;
        }

        Ok(())
    }

    /// CancelAuthentication method
    async fn cancel_authentication(&self, cookie: &str) -> zbus::fdo::Result<()> {
        debug!("Authentication cancled ! {cookie}");
        let Some(sender) = self.session_cancel_signals.get(cookie) else {
            error!("Unable to find session with cookie {}", cookie);
            return Ok(());
        };
        // TODO; Error handling
        sender.send(()).await.unwrap();
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    pkatt::setup_logging();

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
