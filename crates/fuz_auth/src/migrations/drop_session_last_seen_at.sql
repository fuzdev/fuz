-- drop_session_last_seen_at: drop `auth_session.last_seen_at`. The session
-- lifetime is a hard cap set at mint — nothing updates the column post-mint
-- on either spine, so it always equalled `created_at` (a decorative false
-- signal the UIs stopped showing when the listings re-sorted by `created_at`).
ALTER TABLE auth_session DROP COLUMN IF EXISTS last_seen_at;
