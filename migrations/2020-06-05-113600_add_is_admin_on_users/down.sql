CREATE OR REPLACE VIEW postgraphql.users
 AS
 SELECT u.id,
    u.provider,
    u.uid,
    u.encrypted_password,
    u.reset_password_token,
    u.reset_password_sent_at,
    u.remember_created_at,
    u.sign_in_count,
    u.current_sign_in_at,
    u.last_sign_in_at,
    u.current_sign_in_ip,
    u.last_sign_in_ip,
    u.confirmation_token,
    u.confirmed_at,
    u.confirmation_sent_at,
    u.unconfirmed_email,
    u.first_name,
    u.last_name,
    u.email,
    u.tokens,
    u.created_at,
    u.updated_at,
    u.avatar,
    u.admin,
    u.locale,
    COALESCE(json_agg(t.name), '[]'::json) AS tags
   FROM users u
     LEFT JOIN user_tags ut ON ut.user_id = u.id
     LEFT JOIN tags t ON t.id = ut.tag_id
  WHERE u.id = current_setting('jwt.claims.user_id'::text)::integer
  GROUP BY u.id;


ALTER TABLE public.users DROP COLUMN is_admin;