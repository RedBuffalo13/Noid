#[test]
fn listener_registration_is_owned_and_cannot_clear_a_newer_listener(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::stun_hook::{clone_listener_udp_socket, on_listener_socket_bound};
    use std::net::UdpSocket;
    let first = UdpSocket::bind("127.0.0.1:0")?;
    let first_registration = on_listener_socket_bound(&first, false);
    let first_generation = crate::stun_hook::listener_generation(false).ok_or("no first owner")?;
    let second = UdpSocket::bind("127.0.0.1:0")?;
    let second_address = second.local_addr()?;
    let second_registration = on_listener_socket_bound(&second, false);
    let second_generation =
        crate::stun_hook::listener_generation(false).ok_or("no second owner")?;
    let mapping = crate::stun_hook::StunMapping {
        external_addr: ([203, 0, 113, 7], 4020).into(),
        local_port: second_address.port(),
        nat_kind: crate::stun_hook::StunNatKind::Cone,
    };
    assert!(!crate::stun_hook::set_observed_stun_mapping(
        first_generation,
        mapping.clone()
    ));
    assert!(crate::stun_hook::set_observed_stun_mapping(
        second_generation,
        mapping.clone()
    ));
    let mut wrong_port = mapping.clone();
    wrong_port.local_port ^= 1;
    assert!(!crate::stun_hook::set_observed_stun_mapping(
        second_generation,
        wrong_port
    ));
    drop(first_registration);
    assert_eq!(
        clone_listener_udp_socket(false)
            .ok_or("listener registry is empty")?
            .local_addr()?,
        second_address
    );
    drop(second_registration);
    assert!(clone_listener_udp_socket(false).is_none());
    assert!(crate::stun_hook::observed_stun_mapping().is_none());
    assert!(!crate::stun_hook::set_observed_stun_mapping(
        second_generation,
        mapping
    ));
    Ok(())
}
