//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

/// A macro for defining a set of capabilities.
#[macro_export]
macro_rules! caps {
    {$(
        $uri:literal : {
            $( $ability:literal : [
                $( $caveats:tt ),*
            ]),+ $(,)?
        }
    ),* $(,)?} => {
        {
            #[allow(unused_mut)]
            let mut capabilities = $crate::Capabilities::new();
            $(
                let mut ability_list = std::collections::BTreeMap::new();
                $(
                    let caveats = $crate::caveats![$($caveats),*];
                    ability_list.insert($ability.parse()?, caveats);
                )+
                let abilities = $crate::Abilities::from_iter(ability_list)?;
                capabilities.insert(<$crate::ResourceUri as std::str::FromStr>::from_str($uri)?, abilities);
            )*
            capabilities
        }
    };
}

/// A macro for defining a set of abilities.
#[macro_export]
macro_rules! abilities {
    { $( $ability:literal : [ $( $caveats:tt ),* ]),* $(,)? } => {
        {
            let mut abilities = std::collections::BTreeMap::new();
            $(
                let caveats = $crate::caveats![$($caveats),*];
                abilities.insert($ability.parse()?, caveats);
            )*
            $crate::Abilities::from_iter(abilities)?
        }
    };
}

/// A macro for defining a set of caveats.
#[macro_export]
macro_rules! caveats {
    [$({
        $( $caveat:literal : $json:tt ),* $(,)?
    }),* $(,)?] => {
        {
            let mut caveat_list = std::vec::Vec::new();
            $(
                #[allow(unused_mut)]
                let mut caveat = std::collections::BTreeMap::new();
                $(
                    caveat.insert($caveat.to_string(), $crate::serde_json::json!($json));
                )*
                caveat_list.push(caveat);
            )*
            if caveat_list.is_empty() {
                caveat_list.push(std::collections::BTreeMap::new());
            }

            $crate::Caveats::from_iter(caveat_list)?
        }
    };
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{Abilities, Capabilities, Caveats};

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
        };

        let expected_capabilities = {
            let mut capabilities = Capabilities::new();

            capabilities.insert("example://example.com/public/photos/".parse()?, {
                Abilities::from_iter([
                    ("crud/read".parse()?, Caveats::any()),
                    ("crud/delete".parse()?, Caveats::any()),
                ])?
            });

            capabilities.insert("mailto:username@example.com".parse()?, {
                Abilities::from_iter([
                    ("msg/send".parse()?, Caveats::any()),
                    (
                        "msg/receive".parse()?,
                        Caveats::from_iter([BTreeMap::from_iter(vec![
                            ("max_count".into(), serde_json::json!(5)),
                            (
                                "templates".into(),
                                serde_json::json!(["newsletter", "marketing"]),
                            ),
                        ])])?,
                    ),
                ])?
            });

            capabilities.insert("dns:example.com".parse()?, {
                Abilities::from_iter([(
                    "crud/create".parse()?,
                    Caveats::from_iter([
                        BTreeMap::from_iter(vec![("type".into(), serde_json::json!("A"))]),
                        BTreeMap::from_iter(vec![("type".into(), serde_json::json!("CNAME"))]),
                        BTreeMap::from_iter(vec![("type".into(), serde_json::json!("TXT"))]),
                    ])?,
                )])?
            });

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
        }];

        let expected_caveats = Caveats::from_iter([BTreeMap::from_iter(vec![
            ("max_count".into(), serde_json::json!(5)),
            (
                "templates".into(),
                serde_json::json!(["newsletter", "marketing"]),
            ),
        ])])?;

        assert_eq!(caveats, expected_caveats);

        Ok(())
    }

    #[test]
    fn test_abilities_macro() -> anyhow::Result<()> {
        let abilities = abilities! {
            "crud/read": [{}],
            "crud/delete": [{}],
        };

        let expected_abilities = Abilities::from_iter([
            ("crud/read".parse()?, Caveats::any()),
            ("crud/delete".parse()?, Caveats::any()),
        ])?;

        assert_eq!(abilities, expected_abilities);

        Ok(())
    }
}
