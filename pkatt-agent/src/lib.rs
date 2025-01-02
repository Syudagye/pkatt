use identity::{BorrowedIdentity, Identity, IndentityConvertError};
use prompt::PromptInput;
use serde::{Deserialize, Serialize};

pub mod prompt;
pub mod identity;

pub fn setup_logging() {
    color_eyre::install().unwrap_or_else(|_| {
        eprintln!("Unable to setup fancy panic messages, falling back to default panic format")
    });
    env_logger::init();
}

/// Data of an authentication session
#[derive(Debug)]
pub struct Session {
    /// Nature of the authentication
    pub message: String,
    /// Icon of the application
    pub icon_name: String,
    /// Cookied identifying the session
    pub cookie: String,
    /// Users that can be used to authenticate
    pub identities: Vec<Identity>,
    // pub uid_identities: HashMap<u32, IdentityWrapper>,
}

impl Session {
    pub fn new(
        message: String,
        icon_name: String,
        cookie: String,
        identities: Vec<BorrowedIdentity<'_>>,
    ) -> Result<Session, IndentityConvertError> {
        let identities = identities
            .iter()
            .map(<Identity as TryFrom<&BorrowedIdentity<'_>>>::try_from)
            .collect::<Result<Vec<Identity>, IndentityConvertError>>()?;

        Ok(Session {
            message,
            icon_name,
            cookie,
            identities,
        })
    }

    pub fn create_responder_input(&self, id: u32) -> Option<ResponderInput> {
        let identity = self
            .identities
            .iter()
            .find(|i| match i {
                Identity::User { uid, .. } => *uid == id,
                Identity::Group { gid, .. } => *gid == id,
            })?
            .clone();

        Some(ResponderInput {
            agent_uid: nix::unistd::getuid().into(),
            cookie: self.cookie.clone(),
            identity,
        })
    }

    pub fn create_prompt_input(&self) -> PromptInput {
        PromptInput {
            message: self.message.clone(),
            users: self.identities.clone(),
        }
    }
}

/// Data passed to the responder program
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponderInput {
    pub agent_uid: u32,
    pub cookie: String,
    pub identity: Identity,
}
