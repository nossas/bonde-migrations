ALTER TABLE pressure_targets DROP COLUMN created_at;
ALTER TABLE pressure_targets DROP COLUMN updated_at;

DROP TRIGGER pressure_targets_update_at;