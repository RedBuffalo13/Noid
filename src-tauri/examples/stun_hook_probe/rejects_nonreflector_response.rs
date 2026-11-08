#[test]
fn rejects_response_from_unconfigured_source() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::UdpSocket;
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let allowed = server.local_addr()?;
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut request = [0u8; 20];
        let (_, client) = server.recv_from(&mut request)?;
        let mut response = crate::binding_response::binding_response(12);
        response[8..20].copy_from_slice(&request[8..20]);
        let attacker = UdpSocket::bind("127.0.0.1:0")?;
        attacker.send_to(&response, client)?;
        Ok(())
    });
    let client = UdpSocket::bind("127.0.0.1:0")?;
    let result = crate::stun_hook::probe_with_reflectors(&client, 0, &[allowed]);
    worker.join().map_err(|_| "reflector worker panicked")??;
    assert!(result.is_none());
    Ok(())
}
