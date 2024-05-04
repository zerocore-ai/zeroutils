use x25519_dalek::{PublicKey, SharedSecret};

use crate::{AsymmetricKey, PubKey};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An [`x25519`][ref] public key.
///
/// [ref]: https://en.wikipedia.org/wiki/X25519
pub type X25519PubKey<'a> = PubKey<'a, PublicKey>;

/// An [`x25519`][ref] key pair with a shared secret.
///
/// [ref]: https://en.wikipedia.org/wiki/X25519
pub type X25519KeyPair<'a> = X25519Key<'a, SharedSecret>;

pub(crate) type X25519Key<'a, S = ()> = AsymmetricKey<'a, PublicKey, S>;
