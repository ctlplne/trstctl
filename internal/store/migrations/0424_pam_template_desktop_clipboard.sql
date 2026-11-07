-- A269: an access template's clipboard policy for remote desktop sessions:
-- deny (the default), to_target, from_target or both. Existing templates keep
-- their meaning: no clipboard.
ALTER TABLE pam_access_templates ADD COLUMN IF NOT EXISTS desktop_clipboard text NOT NULL DEFAULT 'deny'
    CHECK (desktop_clipboard IN ('deny', 'to_target', 'from_target', 'both'));
