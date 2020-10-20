ALTER TABLE dns_hosted_zones ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE dns_hosted_zones ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE dns_records ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE dns_records ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER dns_records_update_at BEFORE UPDATE ON dns_records FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();
CREATE TRIGGER dns_hosted_zones_update_at BEFORE UPDATE ON dns_hosted_zones FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();