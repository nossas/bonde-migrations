-- add column on table
alter table public.tags add column kind text;
-- update to set a kind user
update public.tags set kind = 'user' where name like 'user_%';

-- add default created_at and updated_at to user_tags
ALTER TABLE public.user_tags ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE public.user_tags ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER user_tags_update_at
    BEFORE UPDATE 
    ON public.user_tags
    FOR EACH ROW
    EXECUTE PROCEDURE public.updated_at_column();

-- add default created_at and updated_at to user
ALTER TABLE public.users ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE public.users ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER users_update_at
    BEFORE UPDATE 
    ON public.users
    FOR EACH ROW
    EXECUTE PROCEDURE public.updated_at_column();