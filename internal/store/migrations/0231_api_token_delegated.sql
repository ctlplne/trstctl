-- A token one person mints for another subject is delegated (F262): it may do
-- that subject's work but never counts as that subject's approval. The projection
-- derives the flag from the api_token.created event's authenticated actor, so a
-- rebuild recovers it for existing history. NULL (rows projected before this
-- column, or seeded outside the event log) is treated as not delegated.
ALTER TABLE api_tokens ADD COLUMN delegated boolean;
