//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

/// A macro for defining a set of capabilities.
#[macro_export]
macro_rules! caps {
    {$(
        $uri:literal : {
            $( $ability:literal : [
                $( $caveats:tt ),+
            ]),+ $(,)?
        }
    ),* $(,)?} => {
        (|| {
            #[allow(unused_mut)]
            let mut capabilities = $crate::Capabilities::new();

            $(
                let mut ability_list = std::collections::BTreeMap::new();
                $(
                    let caveats = $crate::caveats![$($caveats),+]?;
                    ability_list.insert($ability.parse()?, caveats);
                )+
                let abilities = $crate::Abilities::try_from_iter(ability_list)?;
                capabilities.insert(<$crate::ResourceUri as std::str::FromStr>::from_str($uri)?, abilities)?;
            )*

            $crate::Ok(capabilities)
        })()
    };
}

/// A macro for defining a set of abilities.
#[macro_export]
macro_rules! abilities {
    { $( $ability:literal : [ $( $caveats:tt ),* ]),* $(,)? } => {
        (|| {
            let mut map = std::collections::BTreeMap::new();
            $(
                let caveats = $crate::caveats![$($caveats),*]?;
                map.insert($ability.parse()?, caveats);
            )*
            $crate::Abilities::try_from_iter(map)
        })()
    };
}

/// A macro for defining a set of caveats.
#[macro_export]
macro_rules! caveats {
    [$( $json:tt ),* $(,)?] => {
        {
            let mut caveat_list = std::vec::Vec::new();
            $(
                caveat_list.push(
                    $crate::Caveat::try_from(
                        $crate::serde_json::json!($json)
                    )?
                );
            )+

            $crate::Caveats::try_from_iter(caveat_list)
        }
    };
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{Abilities, Capabilities, Caveat, Caveats};

    #[test]
    fn test_capabilities_macro() -> anyhow::Result<()> {
        let capabilities = caps! {
            "example://example.com/public/photos/": {
                "crud/read": [{}],
                "crud/delete": [{}],
            },
            "mailto:username@example.com": {
                "msg/send": [{}],
                "msg/receive": [
                    {
                        "max_count": 5,
                        "templates": [
                            "newsletter",
                            "marketing"
                        ]
                    }
                ]
            },
            "dns:example.com": {
                "crud/create": [
                    {"type": "A"},
                    {"type": "CNAME"},
                    {"type": "TXT"}
                ]
            }
        }?;

        let expected_capabilities = {
            let mut capabilities = Capabilities::new();

            capabilities.insert("example://example.com/public/photos/".parse()?, {
                Abilities::try_from_iter([
                    ("crud/read".parse()?, Caveats::any()),
                    ("crud/delete".parse()?, Caveats::any()),
                ])?
            })?;

            capabilities.insert("mailto:username@example.com".parse()?, {
                Abilities::try_from_iter([
                    ("msg/send".parse()?, Caveats::any()),
                    (
                        "msg/receive".parse()?,
                        Caveats::try_from_iter([Caveat::try_from(json!({
                            "max_count": 5,
                            "templates": ["newsletter", "marketing"]
                        }))?])?,
                    ),
                ])?
            })?;

            capabilities.insert("dns:example.com".parse()?, {
                Abilities::try_from_iter([(
                    "crud/create".parse()?,
                    Caveats::try_from_iter([
                        Caveat::try_from(json!({"type": "A"}))?,
                        Caveat::try_from(json!({"type": "CNAME"}))?,
                        Caveat::try_from(json!({"type": "TXT"}))?,
                    ])?,
                )])?
            })?;

            capabilities
        };

        assert_eq!(capabilities, expected_capabilities);

        Ok(())
    }

    #[test]
    fn test_caveats_macro() -> anyhow::Result<()> {
        let caveats = caveats! [{
            "max_count": 5,
            "templates": ["newsletter", "marketing"]
        }]?;

        let expected_caveats = Caveats::try_from_iter([Caveat::try_from(json!({
            "max_count": 5,
            "templates": ["newsletter", "marketing"]
        }))?])?;

        assert_eq!(caveats, expected_caveats);

        Ok(())
    }

    #[test]
    fn test_abilities_macro() -> anyhow::Result<()> {
        let abilities = abilities! {
            "crud/read": [{}],
            "crud/delete": [{}],
        }?;

        let expected_abilities = Abilities::try_from_iter([
            ("crud/read".parse()?, Caveats::any()),
            ("crud/delete".parse()?, Caveats::any()),
        ])?;

        assert_eq!(abilities, expected_abilities);

        Ok(())
    }
}
