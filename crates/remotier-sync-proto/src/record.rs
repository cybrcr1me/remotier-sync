//! Records on the wire: the plaintext envelope, and the payload structs that go inside it.

use serde::{Deserialize, Serialize};

/// Which table a record came from.
///
/// Serialised as a stable snake_case string, matching the `kind` column of the client's
/// `sync_meta` table. Never reorder or renumber - this is persisted on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Host,
    Group,
    Identity,
    VarDef,
    Setting,
    Workspace,
    /// One machine's open tabs. Keyed by device id, and never applied automatically -
    /// two devices would otherwise overwrite each other continuously.
    DeviceLayout,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Group => "group",
            Self::Identity => "identity",
            Self::VarDef => "var_def",
            Self::Setting => "setting",
            Self::Workspace => "workspace",
            Self::DeviceLayout => "device_layout",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "host" => Self::Host,
            "group" => Self::Group,
            "identity" => Self::Identity,
            "var_def" => Self::VarDef,
            "setting" => Self::Setting,
            "workspace" => Self::Workspace,
            "device_layout" => Self::DeviceLayout,
            // Deliberately not a fallback arm. A kind this build does not know must be
            // skipped, not misfiled - the client's `VarScope::from_db` maps unknown
            // values onto a real variant and that is a bug worth not repeating here.
            _ => return None,
        })
    }
}

/// Which key encrypts a record's payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyRef {
    /// The account's own content key. Readable by this user's devices and nobody else.
    Personal,
    /// A shared group's content key, wrapped for each member. Moving a record into a
    /// shared group re-encrypts it under this on the next push.
    Group { group_id: String },
}

/// One record, as it crosses the network and as the server stores it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// The local row's uuid. Ids are global: the same host is the same id everywhere.
    pub id: String,
    pub kind: RecordKind,
    pub key_ref: KeyRef,
    /// Routing hint only - the payload's copy is authoritative. Present so the server can
    /// serve a shared group's records to its members without decrypting anything.
    pub group_id: Option<String>,
    /// Groups only. Lets the server understand the tree for sharing; same hint status.
    pub parent_id: Option<String>,
    pub sort: i64,
    /// Client epoch-ms. The last-write-wins clock.
    pub updated_at: i64,
    /// The device that wrote this. Breaks an exact `updated_at` tie deterministically.
    pub device_id: String,
    /// Set when the record was deleted. The envelope outlives the row so the deletion can
    /// be told to other devices - without it, the next pull simply resurrects the record.
    pub deleted_at: Option<i64>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    /// XChaCha20-Poly1305 over the JSON of the matching payload struct. Empty for a
    /// tombstone: there is nothing left to encrypt, and shipping the last known state of
    /// a deleted record would be a needless leak.
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// Server-assigned change-log position. Ignored on push, authoritative on pull.
    #[serde(default)]
    pub seq: i64,
}

impl Envelope {
    /// The associated data the payload is sealed against.
    ///
    /// `Vault::seal` in the client uses no AAD, so a sealed blob there is not bound to the
    /// row that owns it. That is survivable for a local database and is not survivable
    /// here: without this, a hostile server could swap two users' ciphertexts, or replay
    /// an old record under a new id, and every client would decrypt it happily.
    ///
    /// Deliberately excludes `seq` (the server sets it) and `group_id` / `sort` (the
    /// payload carries the authoritative copy, so tampering with the hint is detected by
    /// the client comparing the two, not by the cipher).
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(self.id.as_bytes());
        out.push(0x1f);
        out.extend_from_slice(self.kind.as_str().as_bytes());
        out.push(0x1f);
        out.extend_from_slice(self.updated_at.to_be_bytes().as_slice());
        out.push(0x1f);
        out.extend_from_slice(self.device_id.as_bytes());
        out
    }

    pub fn is_tombstone(&self) -> bool {
        self.deleted_at.is_some()
    }
}

/// Base64 for the byte fields, so an envelope is legible JSON rather than an array of
/// 300 integers.
mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Payloads. One per RecordKind, mirroring the client's `db::models` minus every
// secret-bearing field. There is nowhere here to put a password.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostPayload {
    pub group_id: Option<String>,
    pub label: String,
    pub hostname: String,
    pub port: Option<i64>,
    pub identity_id: Option<String>,
    pub jump_host_id: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub tags: Vec<String>,
    pub sort: i64,
    pub username: Option<String>,
    /// `None` means "use the inherited identity", exactly as `hosts.auth_kind` NULL does.
    pub auth_kind: Option<String>,
    /// The key's **fingerprint**, not its id.
    ///
    /// Key rows never sync, and `import_key` / `generate_key` mint a fresh uuid on every
    /// machine, so a synced `key_id` would point at nothing on the far side - or worse, at
    /// a different key that happened to take the id. The fingerprint is the only stable
    /// name a key has across devices. Applying resolves it against the local keychain and
    /// stores NULL when the key is not on this machine.
    pub key_fingerprint: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupPayload {
    pub parent_id: Option<String>,
    pub name: String,
    pub sort: i64,
    pub default_port: Option<i64>,
    pub default_identity_id: Option<String>,
    pub default_jump_host_id: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPayload {
    pub label: String,
    pub username: String,
    pub auth_kind: String,
    /// See [`HostPayload::key_fingerprint`] - same reason.
    pub key_fingerprint: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VarDefPayload {
    pub scope: String,
    pub scope_id: String,
    pub name: String,
    pub label: Option<String>,
    pub default_value: Option<String>,
    pub required: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingPayload {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePayload {
    pub name: String,
    pub layout_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLayoutPayload {
    pub device_name: String,
    pub layout_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            id: "h1".into(),
            kind: RecordKind::Host,
            key_ref: KeyRef::Personal,
            group_id: Some("g1".into()),
            parent_id: None,
            sort: 3,
            updated_at: 1_700_000_000_000,
            device_id: "dev-a".into(),
            deleted_at: None,
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
            seq: 12,
        }
    }

    #[test]
    fn kind_strings_round_trip() {
        for kind in [
            RecordKind::Host,
            RecordKind::Group,
            RecordKind::Identity,
            RecordKind::VarDef,
            RecordKind::Setting,
            RecordKind::Workspace,
            RecordKind::DeviceLayout,
        ] {
            assert_eq!(RecordKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn an_unknown_kind_is_skipped_not_guessed() {
        assert_eq!(RecordKind::parse("host_v2"), None);
    }

    #[test]
    fn aad_covers_the_fields_a_server_could_swap() {
        let base = envelope();

        let mut other_id = base.clone();
        other_id.id = "h2".into();
        assert_ne!(base.aad(), other_id.aad());

        let mut other_kind = base.clone();
        other_kind.kind = RecordKind::Group;
        assert_ne!(base.aad(), other_kind.aad());

        let mut other_clock = base.clone();
        other_clock.updated_at += 1;
        assert_ne!(base.aad(), other_clock.aad());

        let mut other_device = base.clone();
        other_device.device_id = "dev-b".into();
        assert_ne!(base.aad(), other_device.aad());
    }

    #[test]
    fn aad_ignores_what_the_server_legitimately_writes() {
        // The server assigns `seq` after the client sealed the payload, so binding it
        // would make every pulled record fail to open.
        let base = envelope();
        let mut resequenced = base.clone();
        resequenced.seq = 999;
        assert_eq!(base.aad(), resequenced.aad());
    }

    #[test]
    fn aad_is_unambiguous_across_field_boundaries() {
        // Concatenation without a separator would let ("ab", "c") and ("a", "bc") collide.
        let mut a = envelope();
        a.id = "ab".into();
        a.device_id = "c".into();
        let mut b = envelope();
        b.id = "a".into();
        b.device_id = "bc".into();
        assert_ne!(a.aad(), b.aad());
    }

    #[test]
    fn envelope_json_uses_base64_for_bytes() {
        let json = serde_json::to_string(&envelope()).unwrap();
        assert!(json.contains("\"nonce\":\"AQID\""), "{json}");
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nonce, vec![1, 2, 3]);
        assert_eq!(back.ciphertext, vec![4, 5, 6]);
    }

    #[test]
    fn no_payload_has_anywhere_to_put_a_secret() {
        // Not a real assertion so much as a canary: if a field named like a secret is ever
        // added to a payload, this fails and the reviewer has to think about it.
        let json = serde_json::to_string(&HostPayload {
            group_id: None,
            label: "l".into(),
            hostname: "h".into(),
            port: None,
            identity_id: None,
            jump_host_id: None,
            color: None,
            icon: None,
            tags: vec![],
            sort: 0,
            username: None,
            auth_kind: None,
            key_fingerprint: None,
            created_at: 0,
        })
        .unwrap();
        for forbidden in ["password", "passphrase", "secret", "privateKey", "Ref\""] {
            assert!(
                !json.contains(forbidden),
                "{forbidden} leaked into HostPayload"
            );
        }
    }
}
