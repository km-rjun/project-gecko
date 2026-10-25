-- Stable per-session identifier (decision D-040). The keyring and live WebSockets are keyed by it,
-- so rotating the cookie token on unlock does not orphan them. Existing sessions are dropped.
DELETE FROM auth_sessions;
ALTER TABLE auth_sessions ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX auth_sessions_session_id ON auth_sessions(session_id);
