use crate::descriptor::kind::utils::*;
use crate::error::{Error, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NetworkStatusMicrodescConsensus3 {}

impl NetworkStatusMicrodescConsensus3 {
    pub fn parse(input: &str, version: (u32, u32)) -> Result<Self, Error> {
        todo!()
    }
}
