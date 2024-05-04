use std::borrow::Cow;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A key pair with a public and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsymmetricKey<'a, P, S>
where
    P: Clone,
{
    pub(crate) public: Cow<'a, P>,
    pub(crate) private: S,
}

/// A public key.
pub type PubKey<'a, P> = AsymmetricKey<'a, P, ()>;

/// Supported key types.
pub enum KeyType {
    /// An `ed25519` key
    Ed25519,

    /// A `NIST P-256` key
    P256,

    /// A `secp256k1` key
    Secp256k1,
}
