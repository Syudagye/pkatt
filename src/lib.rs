use std::{collections::HashMap, os::unix::ffi::OsStrExt};

use log::debug;
use serde::Deserialize;
use zbus::zvariant::{OwnedValue, Type, Value};

pub mod prompt;

pub fn setup_logging() {
    color_eyre::install().unwrap_or_else(|_| {
        eprintln!("Unable to setup fancy panic messages, falling back to default panic format")
    });
    env_logger::init();
}

#[derive(Debug)]
pub struct IdentityWrapper {
    username: String,
    identity: OwnedIdentity,
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
    pub uid_identities: HashMap<u32, IdentityWrapper>,
}

impl Session {
    pub fn new(
        message: String,
        icon_name: String,
        cookie: String,
        identities: Vec<Identity<'_>>,
    ) -> Self {
        let uid_identities: HashMap<u32, &Identity<'_>> = identities
            .iter()
            .filter(|i| i.kind == "unix-user")
            .filter_map(|i| i.details.get("uid").map(|uid| (uid, i)))
            .filter_map(|(uid, i)| TryInto::<u32>::try_into(uid).ok().map(|uid| (uid, i)))
            .collect();
        // TODO: error handling
        let uid_identities: HashMap<u32, OwnedIdentity> = uid_identities
            .into_iter()
            .map(|(uid, id)| TryInto::<OwnedIdentity>::try_into(id).map(|id| (uid, id)))
            .collect::<Result<HashMap<u32, OwnedIdentity>, <OwnedIdentity as TryFrom<Identity<'_>>>::Error>>(
            )
            .unwrap();
        let uid_identities: HashMap<u32, IdentityWrapper> = uid_identities
            .into_iter()
            .filter_map(|(uid, i)| {
                uzers::get_user_by_uid(uid)
                    .map(|u| u.name().to_str().map(|s| s.to_string()))
                    .flatten()
                    .map(|n| {
                        (
                            uid,
                            IdentityWrapper {
                                username: n,
                                identity: i,
                            },
                        )
                    })
            })
            .collect();

        Self {
            message,
            icon_name,
            cookie,
            uid_identities,
        }
    }

    /// Generates the input to give to the responder through stdin based on the session
    /// informations.
    pub fn serialize_to_responder(&self, uid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut push_in = |s: &str| {
            s.as_bytes().iter().for_each(|b| buf.push(*b));
            buf.push(b'\n');
        };

        push_in(&nix::unistd::getuid().to_string());
        push_in(&self.cookie);

        let wrapper = self.uid_identities.get(&uid).unwrap();
        let identity = &wrapper.identity;
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
        self.uid_identities
            .keys()
            .filter_map(|&id| uzers::get_user_by_uid(id))
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

    fn try_from<'i>(value: Identity<'i>) -> zbus::zvariant::Result<Self> {
        let details: zbus::zvariant::Result<HashMap<String, OwnedValue>> = value
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

impl<'v> TryFrom<&Identity<'v>> for OwnedIdentity {
    type Error = <OwnedValue as TryFrom<Value<'v>>>::Error;

    fn try_from<'i>(value: &Identity<'i>) -> zbus::zvariant::Result<Self> {
        let details: zbus::zvariant::Result<HashMap<String, OwnedValue>> = value
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
