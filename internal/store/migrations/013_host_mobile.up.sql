-- Issue #107 — host kind (agent|mobile) and variant (ios|android) for Mobile Nebula clients.
ALTER TABLE hosts ADD COLUMN kind    TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE hosts ADD COLUMN variant TEXT NOT NULL DEFAULT '';
