mod microdescriptor;
mod network_status_microdesc_consensus_3;
mod server_descriptor;

pub use microdescriptor::Microdescriptor;
pub use network_status_microdesc_consensus_3::NetworkStatusMicrodescConsensus3;
pub use server_descriptor::ServerDescriptor;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Network {
    Accept(String),
    Reject(String),
}
