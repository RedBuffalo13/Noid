//! SEC-1111-05: push the confirmed-contact set into the live P2P node.
//! Username announces and signed endpoint advertisements fan out only to
//! this set — a node that never receives `SetContacts` announces nothing.

use crate::AppState;

/// Read contacts from the DB and notify the node. No-op when the node or
/// the DB is not up yet (wipe, pre-login).
pub async fn push_contacts_to_node(state: &AppState) {
    let Ok(db) = state.require_db().await else {
        return;
    };
    let Ok(contacts) = db.get_contacts().await else {
        return;
    };
    drop(db);
    let Some(tx) = state.p2p() else {
        return;
    };
    let peer_ids: Vec<String> = contacts.into_iter().map(|(id, _, _)| id).collect();
    let _ = tx
        .send(crate::p2p::P2PCommand::SetContacts { peer_ids })
        .await;
}
