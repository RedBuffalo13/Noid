use super::{
    ListenerSocketRegistration, IPV4_LISTENER_SOCKET, IPV6_LISTENER_SOCKET, OBSERVED_MAPPING,
};

impl Drop for ListenerSocketRegistration {
    fn drop(&mut self) {
        let slot = if self.ipv6 {
            &IPV6_LISTENER_SOCKET
        } else {
            &IPV4_LISTENER_SOCKET
        };
        if let Ok(mut current) = slot.write() {
            if current
                .as_ref()
                .is_some_and(|entry| entry.generation == self.generation)
            {
                *current = None;
                if !self.ipv6 {
                    if let Ok(mut mapping) = OBSERVED_MAPPING.write() {
                        if mapping
                            .as_ref()
                            .is_some_and(|(owner, _)| *owner == self.generation)
                        {
                            *mapping = None;
                        }
                    }
                }
            }
        }
    }
}
