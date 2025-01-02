use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Identity {
    User { uid: u32, name: String },
    Group { gid: u32, name: String },
}

/// Context from creating a [`zbus_polkit::policykit1::Identity`] from an [`Identity`]
#[derive(Default)]
pub struct IdentityContext<'v>(HashMap<&'v str, zbus::zvariant::Value<'v>>);

impl Identity {
    /// Convert into a [`zbus_polkit::policykit1::Identity`]
    pub fn create_identity<'v>(
        &'v self,
        ctx: &'v mut IdentityContext<'v>,
    ) -> zbus_polkit::policykit1::Identity<'v> {
        match self {
            Identity::User { uid, .. } => {
                ctx.0.insert("uid", uid.into());
                zbus_polkit::policykit1::Identity {
                    identity_kind: "unix-user",
                    identity_details: &ctx.0,
                }
            }
            Identity::Group { gid, .. } => {
                ctx.0.insert("gid", gid.into());
                zbus_polkit::policykit1::Identity {
                    identity_kind: "unix-group",
                    identity_details: &ctx.0,
                }
            }
        }
    }
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
