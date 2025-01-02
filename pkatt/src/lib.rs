use serde::{Deserialize, Serialize};

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
        identities: Vec<Identity>,
    ) -> Session {
        Session {
            message,
            icon_name,
            cookie,
            identities,
        }
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

/// Designates an entity which can be used to authenticate
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Identity {
    User { uid: u32, name: String },
    Group { gid: u32, name: String },
}

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
