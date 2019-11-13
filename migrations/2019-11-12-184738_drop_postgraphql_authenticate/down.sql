-- FUNCTION: postgraphql.authenticate(text, text)

-- DROP FUNCTION postgraphql.authenticate(text, text);

CREATE OR REPLACE FUNCTION postgraphql.authenticate(
	email text,
	password text)
    RETURNS postgraphql.jwt_token
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE STRICT SECURITY DEFINER 
AS $BODY$
  declare
    users public.users;
  begin
    select u.* into users
    from public.users as u
    where u.email = $1;

    if users.encrypted_password = crypt(password, users.encrypted_password) and users.admin = true then
      return ('admin', users.id)::postgraphql.jwt_token;
    elsif users.encrypted_password = crypt(password, users.encrypted_password) then
      return ('common_user', users.id)::postgraphql.jwt_token;
    else
      return null;
    end if;
  end;
$BODY$;

ALTER FUNCTION postgraphql.authenticate(text, text)
    OWNER TO monkey_user;

COMMENT ON FUNCTION postgraphql.authenticate(text, text)
    IS 'Creates a JWT token that will securely identify a user and give them certain permissions.';
