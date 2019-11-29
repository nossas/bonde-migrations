ALTER TABLE public.community_users ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE public.community_users ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER community_users_update_at BEFORE UPDATE ON community_users FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();