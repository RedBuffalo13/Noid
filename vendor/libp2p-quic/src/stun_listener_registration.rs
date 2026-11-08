/// Owns the registry clone, not independent Quinn tasks or connection streams.
pub(crate) struct ListenerSocketRegistration {
    pub(super) generation: u64,
    pub(super) ipv6: bool,
}
