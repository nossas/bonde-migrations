-- Function to update expires date
CREATE OR REPLACE FUNCTION update_expires()
RETURNS TRIGGER AS $$
BEGIN
    NEW.expires = now()::date + (3 || ' days')::interval;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER invitations_update_expires BEFORE INSERT ON invitations FOR EACH ROW EXECUTE PROCEDURE update_expires();