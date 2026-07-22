ALTER TABLE passwords ADD COLUMN pinned INTEGER DEFAULT 0;
UPDATE passwords SET pinned = 0 WHERE pinned IS NULL;
