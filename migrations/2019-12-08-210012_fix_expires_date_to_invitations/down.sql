DROP FUNCTION IF EXISTS update_expires(days integer);

DROP TRIGGER IF EXISTS invitations_update_expires ON invitations;