ALTER TABLE donations ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE donations ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER donations_update_at BEFORE UPDATE ON donations FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();