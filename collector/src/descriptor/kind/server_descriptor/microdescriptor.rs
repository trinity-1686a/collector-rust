use std::collections::HashMap;

use crate::descriptor::kind::utils::*;
use crate::error::{Error, ErrorKind};

use super::Network;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Microdescriptor {
    pub onion_key: String,
    pub ntor_onion_key: String,
    // pub address: Vec<>
    pub family: Vec<String>,
    pub policy: Option<Network>,
    pub policy6: Option<Network>,
    pub id: HashMap<String, String>,
    // pub pr: Option<String>,
    pub sha256: String,
}

impl Microdescriptor {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        use crate::descriptor::nom_combinators::*;

        if version.0 != 1 || version.1 != 0 {
            return Err(ErrorKind::UnsupportedDesc(format!(
                "server-descriptor v{}.{} is not supported",
                version.0, version.1
            ))
            .into());
        }

        let document_sha256 = sha256::digest(input);

        let mut desc = descriptor_lines(input)?;
        Ok(extract_desc! {
            desc => Microdescriptor rest {
                cert("onion-key") [certif] => {
                    onion_key: certif.to_owned(),
                },
                uniq("ntor-onion-key") [b64_key] => {
                    ntor_onion_key: b64_key.to_string(),
                },
                opt("family") [] => {
                    family: rest.map(|family_strs| family_strs.iter()
                                .map(|fam| fam.to_string())
                                .collect()
                            )
                        .unwrap_or_default(),
                },
                opt("p") [keyword, policy] => {
                    policy: {
                        match keyword {
                            Some("accept") => Some(Network::Accept(policy.unwrap().to_string())),
                            Some("reject") => Some(Network::Reject(policy.unwrap().to_string())),
                            None => None,
                            _ => return Err(ErrorKind::MalformedDesc(
                                "invalid policy kind".to_owned()
                            ).into()),
                        }
                    },
                },
                opt("p6") [keyword, policy] => {
                    policy6: {
                        match keyword {
                            Some("accept") => Some(Network::Accept(policy.unwrap().to_string())),
                            Some("reject") => Some(Network::Reject(policy.unwrap().to_string())),
                            None => None,
                            _ => return Err(ErrorKind::MalformedDesc(
                                "invalid policy kind".to_owned()
                            ).into()),
                        }
                    },
                },
                multi("id") [] => {
                    id: rest.into_iter().map(|e| {
                        if e.values.len() == 2 {
                            Ok((e.values[0].to_string(), e.values[1].to_string()))
                        } else {
                            Err(ErrorKind::MalformedDesc(
                                "invalid argument count for id".to_owned()
                            ))
                        }
                    }).collect::<Result<_, _>>()?,
                },
                opt("__document_sha256") [] => {
                    sha256: document_sha256,
                },
            }
        })
    }
}

mod tests {
    use super::Microdescriptor;
    use crate::descriptor::kind::server_descriptor::Network;

    #[test]
    fn test_parse_microdesc() {
        let document = r#"onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANJo8hjx3JC2NJ4TSPB5zuunHpjWvg2cZD05mXx6IAuhltx1wMgsyLR2
yjivHX7WqbYaLf3XJ0qmBaghvuBApVxRdt1mzrpWFd82j0adU492xg0YYfbSxHSg
EU7E8R+VxAEEOEg49if8/lwLVVMWkwkmh3ZZCvzLXE07M7x/pUrdAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key NpqHUuSR3SYxDvEm+d9BGz1nWda+UKyX64hc3puGUB8
family $05A48DCB220236FCCA21B432C3D4A1FCE8AFCEEB $16D3252B519861248FDEABE05A6F3B97BC510557 $42E817BE07AB39CA3BD7A442AF08E007FF2E3F5B $4F0C498701A41F4D9CA677EA763FD8CA45348E97 $5450CC0E3D08BB001E8229B8990323D11BC63332 $578E007E5E4535FBFEF7758D8587B07B4C8C5D06 $8E6EDA78D8E3ABA88D877C3E37D6D4F0938C7B9F $8F13B91FA8380842993E7C36EEF88BEC5D695587 $90FD830C357A5109AB3C505287713F1AC811174C $91B7A9659CDB5ACF0DEB46DAA82C122C39CC4ADF $9BA84E8C90083676F86C7427C8D105925F13716C $A319D6447B2B4107477E126EE4A2B7C38125149E $B580111855B9C452EB224CA7932B626E28D3C2EA $CD1FD2C1F330A3293DA6068E6A23866D063D6DCB $CFAB19E23290F5BA1F7FF24494D26FBD4E4DF6CE $E2DA7E67DFC30B19C50F2957C0AAFD226143D7C8 $F47B13BFCE4EF48CDEF6C4D7C7A99208EBB972B5
p accept 20-23,43,53,79-81,88,110,143,194,220,389,443,464-465,531,543-544,554,563,587,636,706,749,873,902-904,981,989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8082,8087-8088,8232-8233,8332-8333,8443,8888,9418,9999-10000,11371,19294,19638,50002,64738
p6 accept 20-23,43,53,79-81,88,110,143,194,220,389,443,464-465,531,543-544,554,563,587,636,706,749,873,902-904,981,989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8082,8087-8088,8232-8233,8332-8333,8443,8888,9418,9999-10000,11371,19294,19638,50002,64738
id ed25519 H2XNSv4eCVNaW9WMo6GlYryaU20F3P+Xwbt2v+4mDm0
"#;
        let expected= Microdescriptor {
            onion_key: "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANJo8hjx3JC2NJ4TSPB5zuunHpjWvg2cZD05mXx6IAuhltx1wMgsyLR2
yjivHX7WqbYaLf3XJ0qmBaghvuBApVxRdt1mzrpWFd82j0adU492xg0YYfbSxHSg
EU7E8R+VxAEEOEg49if8/lwLVVMWkwkmh3ZZCvzLXE07M7x/pUrdAgMBAAE=
-----END RSA PUBLIC KEY-----
".to_string(),
            ntor_onion_key: "NpqHUuSR3SYxDvEm+d9BGz1nWda+UKyX64hc3puGUB8".to_string(),
            family: "$05A48DCB220236FCCA21B432C3D4A1FCE8AFCEEB $16D3252B519861248FDEABE05A6F3B97BC510557 $42E817BE07AB39CA3BD7A442AF08E007FF2E3F5B $4F0C498701A41F4D9CA677EA763FD8CA45348E97 $5450CC0E3D08BB001E8229B8990323D11BC63332 $578E007E5E4535FBFEF7758D8587B07B4C8C5D06 $8E6EDA78D8E3ABA88D877C3E37D6D4F0938C7B9F $8F13B91FA8380842993E7C36EEF88BEC5D695587 $90FD830C357A5109AB3C505287713F1AC811174C $91B7A9659CDB5ACF0DEB46DAA82C122C39CC4ADF $9BA84E8C90083676F86C7427C8D105925F13716C $A319D6447B2B4107477E126EE4A2B7C38125149E $B580111855B9C452EB224CA7932B626E28D3C2EA $CD1FD2C1F330A3293DA6068E6A23866D063D6DCB $CFAB19E23290F5BA1F7FF24494D26FBD4E4DF6CE $E2DA7E67DFC30B19C50F2957C0AAFD226143D7C8 $F47B13BFCE4EF48CDEF6C4D7C7A99208EBB972B5".split(" ").map(ToString::to_string).collect(),
            policy: Some(Network::Accept("20-23,43,53,79-81,88,110,143,194,220,389,443,464-465,531,543-544,554,563,587,636,706,749,873,902-904,981,989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8082,8087-8088,8232-8233,8332-8333,8443,8888,9418,9999-10000,11371,19294,19638,50002,64738".to_string())),
            policy6: Some(Network::Accept("20-23,43,53,79-81,88,110,143,194,220,389,443,464-465,531,543-544,554,563,587,636,706,749,873,902-904,981,989-995,1194,1220,1293,1500,1533,1677,1723,1755,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8082,8087-8088,8232-8233,8332-8333,8443,8888,9418,9999-10000,11371,19294,19638,50002,64738".to_string())),
            id: [("ed25519".to_string(), "H2XNSv4eCVNaW9WMo6GlYryaU20F3P+Xwbt2v+4mDm0".to_string())].into_iter().collect(),
            sha256: "13a445a97c674740cb6c3e99ccc353cc0257469fa9857fca3aedb734ab2fd435".to_string(),
        };

        let parsed = Microdescriptor::parse(document, (1, 0)).unwrap();
        assert_eq!(parsed, expected)
    }
}
