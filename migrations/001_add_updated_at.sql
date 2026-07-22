ALTER TABLE passwords ADD COLUMN updated_at TIMESTAMP;
UPDATE passwords SET updated_at = created_at WHERE updated_at IS NULL;
