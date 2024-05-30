use std::collections::HashMap;

use log::debug;
use serde::Deserialize;
use zbus::zvariant::{OwnedValue, Result, Type, Value};

pub mod prompt;

pub fn setup_logging() {
    color_eyre::install().unwrap_or_else(|_| {
        eprintln!("Unable to setup fancy panic messages, falling back to default panic format")
    });
    env_logger::init();
}

/// Data of an authentication session
#[derive(Debug)]
pub struct Session {
    pub action_id: String,
    pub message: String,
    pub icon_name: String,
    pub cookie: String,
    pub identities: Vec<OwnedIdentity>,
    pub selected_identity_index: usize,
}

impl Session {
    /// Generates the input to give to the responder through stdin based on the session
    /// informations.
    pub fn serialize_to_responder(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut push_in = |s: &str| {
            s.as_bytes().iter().for_each(|b| buf.push(*b));
            buf.push(b'\n');
        };

        push_in(&nix::unistd::getuid().to_string());
        push_in(&self.cookie);

        let identity = &self.identities[self.selected_identity_index];
        push_in(&identity.kind);

        debug!("{:?}", identity);

        let key: &str;
        let id: &OwnedValue;
        if let Some(uid) = identity.details.get("uid") {
            key = "uid";
            id = uid;
        } else if let Some(gid) = identity.details.get("gid") {
            key = "gid";
            id = gid;
        } else {
            todo!("handle error");
        }
        push_in(&key);
        push_in(&id.to_string()[7..]); // Remove the "uint32 " prefix

        buf
    }
}

/// Helper struct that implements serde::Deserialize
#[derive(Deserialize, Type, PartialEq, Debug)]
pub struct Identity<'s> {
    pub kind: &'s str,
    pub details: HashMap<&'s str, Value<'s>>,
}

/// Same as identity, but no references
#[derive(Type, PartialEq, Debug)]
pub struct OwnedIdentity {
    pub kind: String,
    pub details: HashMap<String, OwnedValue>,
}

impl<'v> TryFrom<Identity<'v>> for OwnedIdentity {
    type Error = <OwnedValue as TryFrom<Value<'v>>>::Error;

    fn try_from<'i>(value: Identity<'i>) -> Result<Self> {
        let details: Result<HashMap<String, OwnedValue>> = value
            .details
            .iter()
            .map(|(&k, v)| match v.try_into() {
                Ok(v) => Ok((k.to_owned(), v)),
                Err(e) => Err(e),
            })
            .collect();
        Ok(Self {
            kind: value.kind.to_owned(),
            details: details?,
        })
    }
}
