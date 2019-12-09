ALTER TABLE public.invitations ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE public.invitations ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER invitations_update_at BEFORE UPDATE ON invitations FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();