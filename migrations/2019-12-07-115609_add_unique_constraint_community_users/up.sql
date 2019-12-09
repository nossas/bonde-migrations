ALTER TABLE public.community_users
    ADD CONSTRAINT community_users_unique UNIQUE (community_id, user_id, role);