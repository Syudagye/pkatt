use std::{collections::HashMap, fs::File, io::Read, os::unix::ffi::OsStrExt};

use log::debug;
use serde::Deserialize;
use smol::channel::Sender;
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
    /// Nature of the authentication
    pub message: String,
    /// Icon of the application
    pub icon_name: String,
    /// Cookied identifying the session
    pub cookie: String,
    /// Users that can be used to authenticate
    pub identities: Vec<OwnedIdentity>,
    pub selected_identity_index: usize,
    /// Called when the authentication is canceled by polkit
    pub cancel_signal: Sender<()>,
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

    pub fn serialize_users_to_prompt(&self) -> Vec<u8> {
        self.identities
            .iter()
            .filter(|id| id.kind.as_str() == "unix-user")
            .filter_map(|id| id.details.get("uid"))
            .filter_map(|id| id.try_into().ok())
            .filter_map(|id: u32| uzers::get_user_by_uid(id))
            .map(|u| u.name().as_bytes().to_owned())
            .flatten()
            .collect()
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
