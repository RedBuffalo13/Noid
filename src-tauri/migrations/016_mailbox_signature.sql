-- S6: persist the sender's envelope signature so the RECIPIENT can verify
-- it end-to-end — previously the mailbox verified it at Store and dropped
-- it, leaving the retrieve path trusting the mailbox absolutely.
ALTER TABLE mailbox_storage ADD COLUMN signature BLOB;
