pub mod database;
pub mod message_store;
pub mod contact_store;
pub mod room_store;
pub mod profile_store;
pub mod pending_message_store;
pub mod shared_folder_store;
pub mod ratchet_store;
pub mod prekey_store;
pub mod mailbox_store;
pub mod room_invite_store;

pub use database::Database;

#[cfg(test)]
pub(crate) mod db_test;
#[cfg(test)]
mod message_store_test;
#[cfg(test)]
mod contact_store_test;
#[cfg(test)]
mod pending_message_store_test;
#[cfg(test)]
mod prekey_store_test;
#[cfg(test)]
mod mailbox_store_test;
#[cfg(test)]
mod ratchet_store_test;
#[cfg(test)]
mod profile_store_test;
#[cfg(test)]
mod room_store_test;
#[cfg(test)]
mod shared_folder_store_test;
#[cfg(test)]
mod room_invite_store_test;
