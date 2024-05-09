use std::{fs, path::Path};

use crate::ConfigResult;

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// The main configuration trait.
pub trait MainConfig {
    /// Validates the configuration.
    fn validate(&self) -> ConfigResult<()>;

    /// Creates a new `ZerodbConfig` from a toml file.
    fn from_file(path: impl AsRef<Path>) -> ConfigResult<Self>
    where
        Self: Sized + for<'de> serde::Deserialize<'de>,
    {
        let config = fs::read_to_string(path)?;
        let config = toml::from_str(&config)?;
        Ok(config)
    }

    /// Creates a new `ZerodbConfig` from a toml string.
    fn from_string(config: impl AsRef<str>) -> ConfigResult<Self>
    where
        Self: Sized + for<'de> serde::Deserialize<'de>,
    {
        let config = toml::from_str(config.as_ref())?;
        Ok(config)
    }
}
