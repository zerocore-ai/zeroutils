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

/// A macro for defining a set of capabilities.
#[macro_export]
macro_rules! caps_def {
    {$(
        $uri:literal : {
            $( $ability:literal : [
                $( $caveatsjtd:tt ),*
            ]),+ $(,)?
        }
    ),* $(,)?} => {
        (|| {
            let mut caps_def = $crate::CapabilitiesDefinition::new();
            $(
                $({
                    let caveatsjtd =  $crate::caveats_def![$($caveatsjtd),*]?;
                    caps_def.insert($crate::CapabilityDefinitionTuple($uri.parse()?, $ability.parse()?, caveatsjtd));
                })+
            )*
            $crate::Ok(caps_def)
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

/// A macro for defining the type of caveats that are allowed for a capability.
#[macro_export]
macro_rules! caveats_def {
    [$( $json:tt ),* $(,)?] => {
        (|| {
            let caveat_array = [
                $(
                    $crate::serde_json::json!($json)
                ),*
            ];

            $crate::CaveatsDefinition::try_from_iter(caveat_array)
        })()
    };
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{Abilities, Capabilities, Caveat, Caveats, CaveatsDefinition};

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
    fn test_capabilities_definition_macro() -> anyhow::Result<()> {
        // let definition = caps_def! { "zerodb://": { "db/table/read": [] } }?;

        // let definition = caps_def! {
        //     "example://example.com/public/photos/": {
        //         "crud/read": [
        //             {
        //                 "properties": {
        //                     "status": { "type": "string" }
        //                 },
        //                 "optionalProperties": {
        //                     "public": { "type": "boolean" }
        //                 }
        //             }
        //         ],
        //         "crud/delete": [{}],
        //     },
        // }?;

        // let expected_definition = {
        //     let mut capabilities = Capabilities::new();

        //     capabilities.insert("example://example.com/public/photos/".parse()?, {
        //         Abilities::try_from_iter([
        //             ("crud/read".parse()?, Caveats::any()),
        //             ("crud/delete".parse()?, Caveats::any()),
        //         ])?
        //     })?;

        //     CapabilitiesDefinition::try_from_iter(capabilities)?
        // };

        // assert_eq!(definition, expected_definition);

        Ok(())
    }

    #[test]
    fn test_caveats_def_macro() -> anyhow::Result<()> {
        let caveats = caveats_def! [
            {
                "properties": {
                    "maximum_allowed": { "type": "int32" }
                }
            },
            {
                "properties": {
                    "status": { "type": "string" }
                },
                "optionalProperties": {
                    "public": { "type": "boolean" }
                }
            }
        ]?;

        let expected_caveats = CaveatsDefinition::try_from_iter([
            json!({
                "properties": {
                    "maximum_allowed": { "type": "int32" }
                }
            }),
            json!({
                "properties": {
                    "status": { "type": "string" }
                },
                "optionalProperties": {
                    "public": { "type": "boolean" }
                }
            }),
        ])?;

        assert_eq!(caveats, expected_caveats);

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
