use std::{
    collections::HashMap,
    io::Write,
    process::{Command, Stdio},
};

use log::{debug, error, info};
use pam::Client;
use pkatt::{Identity, PromptResponse, Session};
use serde::Deserialize;
use smol::{channel::Sender, pin, stream::StreamExt};
use zbus::{interface, zvariant::Type};

/// Global State for the agent
pub struct Agent {
    session_cancel_signals: HashMap<String, Sender<()>>,
    promp_path: String,
}

impl Agent {
    pub fn new(promp_path: String) -> Agent {
        Agent {
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
        identities: Vec<BorrowedIdentity<'_>>,
    ) -> zbus::fdo::Result<()> {
        debug!("Authentication asked !");
        debug!("action_id: {action_id}, message: {message}, icon_name: {icon_name}, details: {details:?}, cookie: {cookie}, identities: {identities:?}");

        let identities = match identities
            .iter()
            .map(<Identity as TryFrom<&BorrowedIdentity<'_>>>::try_from)
            .collect::<Result<Vec<Identity>, IndentityConvertError>>()
        {
            Ok(s) => s,
            Err(e) => {
                error!("Error parsing identities: {:?}", e);
                return Ok(());
            }
        };
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

        let prompt_input = session.create_prompt_input();
        let prompt_data = match serde_json::to_string(&prompt_input) {
            Ok(data) => data,
            Err(e) => {
                error!("Error serializing prompt input: {}", e);
                return Ok(());
            }
        };
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
            stdin.write(&prompt_data.as_bytes()).unwrap();
            drop(stdin);

            let res = smol::future::race(
                async {
                    let _ = cancel_receiver.next().await;
                    debug!("Received stop signal, stopping sesssion");
                    None
                },
                async {
                    let exit = promp_child.wait().unwrap();
                    Some(exit.success())
                },
            )
            .await;

            match res {
                Some(true) => (),
                Some(false) => {
                    info!("Prompt terminated unexpectedly, restarting it");
                    attempts -= 1;
                    continue;
                }
                None => return Ok(()),
            }

            let stdout = promp_child.stdout.take().unwrap();
            let response: PromptResponse = match serde_json::from_reader(stdout) {
                Ok(res) => res,
                Err(e) => {
                    error!("Error parsing response from the prompt: {}", e);
                    return Ok(());
                }
            };

            // TODO: Check passord with PAM
            let Some(name) = session.get_user_or_group_name(response.id) else {
                error!("uid or gid returned by the prompt is not valid");
                attempts -= 1;
                continue;
            };

            if authenticate(name, &response.password) {
                let mut responder = Command::new("target/debug/pkatt-responder")
                    .stdin(Stdio::piped())
                    .stdout(std::io::stdout())
                    .spawn()
                    .expect("Unable to spawn responder");

                let data = session.create_responder_input(response.id).unwrap();

                let _ = {
                    let resp_stdin = responder.stdin.take().unwrap();
                    serde_json::to_writer(resp_stdin, &data).unwrap();
                };

                let resp_out = responder.wait().unwrap();

                if resp_out.success() {
                    break;
                }
            }

            attempts -= 1;
            if attempts == 0 {
                error!("All attempts failed, stopping session");
                return Ok(());
            }

            error!("Authentication Failed, {} attempts remaining", attempts);
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

/// Attempts to authenticate the user using PAM
fn authenticate(user: &str, password: &str) -> bool {
    let mut auth = Client::with_password("login").expect("Failed to init PAM client!");
    auth.conversation_mut().set_credentials(user, password);
    auth.authenticate().is_ok()
}

/// Helper struct that implements [`serde::Deserialize`]
///
/// To be used to parse identities input from [`BeginAuthentication()`][begin-auth] with zbus
/// interface
///
/// begin-auth: https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.html#eggdbus-method-org.freedesktop.PolicyKit1.AuthenticationAgent.BeginAuthentication
#[derive(Debug, Deserialize, Type)]
pub struct BorrowedIdentity<'s> {
    pub kind: &'s str,
    pub details: HashMap<&'s str, zbus::zvariant::Value<'s>>,
}

impl<'v> TryFrom<&BorrowedIdentity<'v>> for Identity {
    type Error = IndentityConvertError;

    fn try_from(value: &BorrowedIdentity<'v>) -> Result<Self, Self::Error> {
        match value.kind {
            "unix-user" => {
                let uid_v = value
                    .details
                    .get("uid")
                    .ok_or(IndentityConvertError::IncorrectDetails)?;
                let uid = TryInto::<u32>::try_into(uid_v)
                    .map_err(|_| IndentityConvertError::ValueParseError)?;
                let name =
                    uzers::get_user_by_uid(uid).ok_or(IndentityConvertError::UnknownUserOrGroup)?;
                Ok(Self::User {
                    uid,
                    name: name
                        .name()
                        .to_str()
                        .ok_or(IndentityConvertError::ValueParseError)?
                        .to_string(),
                })
            }
            "unix-group" => {
                let gid_v = value
                    .details
                    .get("gid")
                    .ok_or(IndentityConvertError::IncorrectDetails)?;
                let gid = TryInto::<u32>::try_into(gid_v)
                    .map_err(|_| IndentityConvertError::ValueParseError)?;
                let name = uzers::get_group_by_gid(gid)
                    .ok_or(IndentityConvertError::UnknownUserOrGroup)?;
                Ok(Self::Group {
                    gid,
                    name: name
                        .name()
                        .to_str()
                        .ok_or(IndentityConvertError::ValueParseError)?
                        .to_string(),
                })
            }
            _ => Err(IndentityConvertError::UnknownKind),
        }
    }
}

#[derive(Debug)]
pub enum IndentityConvertError {
    UnknownKind,
    IncorrectDetails,
    ValueParseError,
    UnknownUserOrGroup,
}
