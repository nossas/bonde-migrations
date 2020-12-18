ALTER TABLE pressure_targets ADD COLUMN created_at TIMESTAMP DEFAULT now();
ALTER TABLE pressure_targets ADD COLUMN updated_at TIMESTAMP DEFAULT now();

CREATE TRIGGER pressure_targets_update_at BEFORE UPDATE ON pressure_targets FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();