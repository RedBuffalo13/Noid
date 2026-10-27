/// Максимальный размер сообщения для DHT (1KB лимит Kademlia)
pub const MAX_DHT_MESSAGE_SIZE: usize = 1024;

/// Максимальный размер значения в DHT-записи (prekey bundle, username,
/// mailbox pointer). libp2p-kad PUT_VALUE frames cap at
/// `DEFAULT_MAX_PACKET_SIZE` = 16KiB — larger values never reach remote
/// peers — while `MemoryStore` accepts 65KiB. 12KiB leaves margin for
/// the record key and protobuf envelope inside the frame.
pub const MAX_DHT_RECORD_BYTES: usize = 12 * 1024;

/// Максимальное время жизни записи в DHT (24 часа)
pub const MAX_DHT_TTL_SECONDS: u64 = 86400;
