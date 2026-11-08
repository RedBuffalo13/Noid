#[test]
fn generates_a_fresh_transaction_per_probe() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::UdpSocket;
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let allowed = server.local_addr()?;
    let worker = std::thread::spawn(move || -> std::io::Result<Vec<[u8; 12]>> {
        let mut transactions = Vec::new();
        for _ in 0..2 {
            let mut request = [0u8; 20];
            let (_, client) = server.recv_from(&mut request)?;
            let mut tx = [0u8; 12];
            tx.copy_from_slice(&request[8..20]);
            transactions.push(tx);
            let mut response = crate::binding_response::binding_response(12);
            response[8..20].copy_from_slice(&tx);
            server.send_to(&response, client)?;
        }
        Ok(transactions)
    });
    let client = UdpSocket::bind("127.0.0.1:0")?;
    let first = crate::stun_hook::probe_with_reflectors(&client, 0, &[allowed]);
    let second = crate::stun_hook::probe_with_reflectors(&client, 0, &[allowed]);
    let transactions = worker.join().map_err(|_| "reflector worker panicked")??;
    assert!(first.is_some() && second.is_some());
    assert_eq!(transactions.len(), 2);
    assert_ne!(transactions[0], transactions[1]);
    Ok(())
}
