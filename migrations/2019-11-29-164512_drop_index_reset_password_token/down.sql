-- Index: index_users_on_reset_password_token

CREATE UNIQUE INDEX index_users_on_reset_password_token
    ON public.users USING btree
    (reset_password_token COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
