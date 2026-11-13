//! Decoy profile auto-population (Q08/A1, decision V5).
//!
//! An empty profile undermines the cover: a messenger that was never used
//! is itself suspicious for an established install. `seed_decoy_profile`
//! writes a plausible, lightly-used account — a handful of contacts with
//! mundane short history, a room or two, a generic profile — so the decoy
//! opens looking like a real-but-quiet identity.
//!
//! Anti-template rules: contact/message counts, names, phrasing mix and
//! timestamps all vary per seed (`rand`), fake PeerIds come from fresh
//! CSPRNG keypairs (they can never collide with real peers), and the
//! function is idempotent — it only fills an EMPTY contact list so a
//! second decoy login never rewrites the seeded history.

use anyhow::Result;
use rand::RngExt;

/// Mundane one-liners — deliberately boring and low-specificity so they
/// cannot contradict anything. Mixed RU/EN matches the app's user base.
const PHRASES: &[&str] = &[
    "ок",
    "понял",
    "как дела?",
    "нормально, ты как?",
    "завтра созвонимся",
    "окей, договорились",
    "привет",
    "привет!",
    "на связи",
    "потом напишу",
    "спасибо",
    "ага",
    "увидел",
    "занят, позже отвечу",
    "давай в выходные",
    "ок, без проблем",
    "я дома",
    "уже еду",
    "скинь потом",
    "гуд",
    "спокойной ночи",
    "доброе утро",
    "на месте",
    "погнали",
    "ок, напишу",
    "принято",
    "хорошо",
    "до вечера",
    "hi",
    "ok",
    "sure",
    "later",
    "see you",
];

const NAMES: &[&str] = &[
    "Аня", "Макс", "Дима", "Оля", "Сергей", "Ира", "Костя", "Наташа",
    "Вова", "Лена", "Петя", "Саша", "Миша", "Юля", "Андрей", "Катя",
    "Alex", "Sam", "Mike", "Anna",
];

const ROOM_NAMES: &[&str] = &["Семья", "Друзья", "Работа", "Чат", "Группа"];

/// Populate an empty decoy profile. No-op when contacts already exist —
/// seeded content must look stable across logins.
pub async fn seed_decoy_profile(
    db: &crate::db::Database,
    manager: &crate::security::manager::SecurityManager,
    my_peer_id: &str,
) -> Result<()> {
    if !db.get_contacts().await?.is_empty() {
        return Ok(());
    }
    

    // Generic nickname — never echoes the real profile's name (the real
    // one isn't accessible here anyway).
    let nick = NAMES[rand::rng().random_range(0..NAMES.len())];
    let _ = db.update_profile(nick, None).await;

    // 3–6 contacts with plausible names and fresh random PeerIds.
    let n_contacts = rand::rng().random_range(3..=6usize);
    let mut names: Vec<&str> = NAMES.to_vec();
    // Fisher–Yates-lite: pick without replacement.
    let mut contact_peers = Vec::new();
    for _ in 0..n_contacts {
        let i = rand::rng().random_range(0..names.len());
        let name = names.remove(i);
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_string();
        db.add_contact(&peer, name, None).await?;
        contact_peers.push(peer);
    }

    // 1–2 rooms, owned by the decoy identity, members = seeded contacts.
    let n_rooms = rand::rng().random_range(1..=2usize);
    let n_room_members = rand::rng().random_range(2..=contact_peers.len());
    for room_name in ROOM_NAMES.iter().take(n_rooms) {
        let room_id = uuid::Uuid::new_v4().to_string();
        let key: [u8; 32] = rand::random();
        db.create_room_full(&room_id, room_name, &key, Some(my_peer_id), None, 0)
            .await?;
        for peer in contact_peers.iter().take(n_room_members) {
            db.add_room_member(&room_id, peer, true).await?;
        }
    }

    // Message history: 4–12 messages per contact, both directions,
    // spread over the last 3–35 days at plausible daytime hours.
    for peer in &contact_peers {
        let n_msgs = rand::rng().random_range(4..=12usize);
        for _ in 0..n_msgs {
            let days_ago = rand::rng().random_range(3..=35i64);
            let hour = rand::rng().random_range(8..=23u32);
            let minute = rand::rng().random_range(0..60u32);
            let ts = (chrono::Utc::now()
                - chrono::Duration::days(days_ago)
                - chrono::Duration::hours(24 - hour as i64)
                + chrono::Duration::minutes(minute as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let incoming = rand::rng().random_bool(0.45);
            let (from, to) = if incoming {
                (peer.as_str(), my_peer_id)
            } else {
                (my_peer_id, peer.as_str())
            };
            let text = PHRASES[rand::rng().random_range(0..PHRASES.len())];
            let blob = manager.encrypt(text.as_bytes())?;
            db.add_message_with_timestamp(
                &uuid::Uuid::new_v4().to_string(),
                from,
                to,
                &blob,
                &ts,
            )
            .await?;
        }
    }
    Ok(())
}
