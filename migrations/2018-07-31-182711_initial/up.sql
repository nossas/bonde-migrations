-- Your SQL goes here

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4 (Debian 10.4-2.pgdg90+1)
-- Dumped by pg_dump version 10.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: microservices; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA microservices;


ALTER SCHEMA microservices OWNER TO postgres;

--
-- Name: pgjwt; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA pgjwt;


ALTER SCHEMA pgjwt OWNER TO postgres;

--
-- Name: postgraphile_watch; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA postgraphile_watch;


ALTER SCHEMA postgraphile_watch OWNER TO postgres;

--
-- Name: postgraphql; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA postgraphql;


ALTER SCHEMA postgraphql OWNER TO postgres;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';


--
-- Name: hstore; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA public;


--
-- Name: EXTENSION hstore; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION hstore IS 'data type for storing sets of (key, value) pairs';


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_stat_statements IS 'track execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: unaccent; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS unaccent WITH SCHEMA public;


--
-- Name: EXTENSION unaccent; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION unaccent IS 'text search dictionary that removes accents';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET search_path = microservices, pg_catalog;

--
-- Name: jwt_token; Type: TYPE; Schema: microservices; Owner: postgres
--

CREATE TYPE jwt_token AS (
  role text,
  user_id integer
);


ALTER TYPE jwt_token OWNER TO postgres;

SET search_path = postgraphql, pg_catalog;

--
-- Name: facebook_activist_search_result_type; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE facebook_activist_search_result_type AS (
  fb_context_recipient_id text,
  fb_context_sender_id text,
  data jsonb,
  messages tsvector,
  quick_replies text[],
  created_at timestamp without time zone,
  updated_at timestamp without time zone,
  id integer
);


ALTER TYPE facebook_activist_search_result_type OWNER TO postgres;

--
-- Name: facebook_bot_campaigns_type; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE facebook_bot_campaigns_type AS (
  facebook_bot_configuration_id integer,
  name text,
  segment_filters jsonb,
  total_impacted_activists integer
);


ALTER TYPE facebook_bot_campaigns_type OWNER TO postgres;

--
-- Name: get_facebook_bot_campaign_activists_by_campaign_type; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE get_facebook_bot_campaign_activists_by_campaign_type AS (
  id integer,
  facebook_bot_campaign_id integer,
  facebook_bot_activist_id integer,
  received boolean,
  log jsonb,
  created_at timestamp without time zone,
  updated_at timestamp without time zone,
  fb_context_recipient_id text,
  fb_context_sender_id text,
  data jsonb,
  messages tsvector,
  quick_replies text[],
  interaction_dates timestamp without time zone[]
);


ALTER TYPE get_facebook_bot_campaign_activists_by_campaign_type OWNER TO postgres;

--
-- Name: jwt_token; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE jwt_token AS (
  role text,
  user_id integer
);


ALTER TYPE jwt_token OWNER TO postgres;

--
-- Name: twilio_calls_arguments; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE twilio_calls_arguments AS (
  activist_id integer,
  widget_id integer,
  "from" text,
  "to" text,
  twilio_call_sid text
);


ALTER TYPE twilio_calls_arguments OWNER TO postgres;

--
-- Name: watch_twilio_call_transition_record_set; Type: TYPE; Schema: postgraphql; Owner: postgres
--

CREATE TYPE watch_twilio_call_transition_record_set AS (
  widget_id integer,
  activist_id integer,
  twilio_call_id integer,
  twilio_call_account_sid text,
  twilio_call_call_sid text,
  twilio_call_from text,
  twilio_call_to text,
  twilio_call_transition_id integer,
  twilio_call_transition_sequence_number integer,
  twilio_call_transition_status text,
  twilio_call_transition_call_duration text,
  twilio_call_transition_created_at timestamp without time zone,
  twilio_call_transition_updated_at timestamp without time zone
);


ALTER TYPE watch_twilio_call_transition_record_set OWNER TO postgres;

SET search_path = public, pg_catalog;

--
-- Name: email; Type: DOMAIN; Schema: public; Owner: postgres
--

CREATE DOMAIN email AS citext
CONSTRAINT email_check CHECK ((VALUE ~ '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'::citext));


ALTER DOMAIN email OWNER TO postgres;

--
-- Name: status_mobilization; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE status_mobilization AS ENUM (
  'active',
  'archived'
);


ALTER TYPE status_mobilization OWNER TO postgres;

SET search_path = microservices, pg_catalog;

--
-- Name: create_community_dns(json); Type: FUNCTION; Schema: microservices; Owner: postgres
--

CREATE FUNCTION create_community_dns(data json) RETURNS json
LANGUAGE plpgsql
AS $_$
declare
_community public.communities;
_dns_hosted_zone public.dns_hosted_zones;
_dns public.dns_hosted_zones;
begin
  -- to execute function in api-v1
  -- if current_role <> 'microservices' then
  --     raise 'permission_denied';
  -- end if;

  select * from public.communities c where c.id = ($1->>'community_id')::integer
  into _community;

  if _community is null then
    raise 'community_not_found';
  end if;

  select *
  from public.dns_hosted_zones
  where community_id = _community.id and domain_name = $1->>'domain_name'
  into _dns;

  if _dns is null then
    insert into public.dns_hosted_zones(community_id, domain_name, comment, created_at, updated_at, ns_ok)
    values (
      _community.id, $1->>'domain_name', $1->>'comment', now(), now(), false
    )
    returning * into _dns_hosted_zone;
  else
    select *
    from public.dns_hosted_zones
    where community_id = _community.id and domain_name = $1->>'domain_name'
    into _dns_hosted_zone;
  end if;

  -- after create dns_hosted_zone perform route53
  perform pg_notify('dns_channel',pgjwt.sign(json_build_object(
        'action', 'create_hosted_zone',
        'id', _dns_hosted_zone.id,
        'domain', _dns_hosted_zone.domain_name,
        'created_at', _dns_hosted_zone.created_at,
        'sent_to_queuing', now(),
        'jit', now()::timestamp
  ), public.configuration('jwt_secret'), 'HS512'));

          return json_build_object(
            'id', _dns_hosted_zone.id,
            'community_id', _dns_hosted_zone.community_id,
            'domain_name', _dns_hosted_zone.domain_name,
            'comment', _dns_hosted_zone.comment,
            'ns_ok', _dns_hosted_zone.ns_ok
          );
end;
$_$;


ALTER FUNCTION microservices.create_community_dns(data json) OWNER TO postgres;

SET search_path = public, pg_catalog;

--
-- Name: locale_names(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION locale_names() RETURNS text[]
LANGUAGE sql IMMUTABLE
AS $$
select '{pt-BR, es, en}'::text[];
$$;


ALTER FUNCTION public.locale_names() OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE users (
  id integer NOT NULL,
  provider character varying NOT NULL,
  uid character varying DEFAULT ''::character varying NOT NULL,
  encrypted_password character varying DEFAULT ''::character varying NOT NULL,
  reset_password_token character varying,
  reset_password_sent_at timestamp without time zone,
  remember_created_at timestamp without time zone,
  sign_in_count integer DEFAULT 0 NOT NULL,
  current_sign_in_at timestamp without time zone,
  last_sign_in_at timestamp without time zone,
  current_sign_in_ip character varying,
  last_sign_in_ip character varying,
  confirmation_token character varying,
  confirmed_at timestamp without time zone,
  confirmation_sent_at timestamp without time zone,
  unconfirmed_email character varying,
  first_name character varying,
  last_name character varying,
  email character varying,
  tokens text,
  created_at timestamp without time zone,
  updated_at timestamp without time zone,
  avatar character varying,
  admin boolean,
  locale text DEFAULT 'pt-BR'::text NOT NULL,
  CONSTRAINT localechk CHECK ((locale = ANY (locale_names())))
);


ALTER TABLE users OWNER TO postgres;

SET search_path = microservices, pg_catalog;

--
-- Name: current_user(); Type: FUNCTION; Schema: microservices; Owner: postgres
--

CREATE FUNCTION "current_user"() RETURNS public.users
LANGUAGE sql STABLE
AS $$
select
*
from
public.users
where
id = current_setting('jwt.claims.user_id')::integer
$$;


ALTER FUNCTION microservices."current_user"() OWNER TO postgres;

--
-- Name: FUNCTION "current_user"(); Type: COMMENT; Schema: microservices; Owner: postgres
--

COMMENT ON FUNCTION "current_user"() IS 'Gets the user who was indentified by our JWT.';


--
-- Name: current_user_id(); Type: FUNCTION; Schema: microservices; Owner: postgres
--

CREATE FUNCTION current_user_id() RETURNS integer
LANGUAGE sql
AS $$
select id from microservices.current_user();
$$;


ALTER FUNCTION microservices.current_user_id() OWNER TO postgres;

SET search_path = pgjwt, pg_catalog;

--
-- Name: algorithm_sign(text, text, text); Type: FUNCTION; Schema: pgjwt; Owner: postgres
--

CREATE FUNCTION algorithm_sign(signables text, secret text, algorithm text) RETURNS text
LANGUAGE sql
AS $$
WITH
alg AS (
  SELECT CASE
  WHEN algorithm = 'HS256' THEN 'sha256'
  WHEN algorithm = 'HS384' THEN 'sha384'
  WHEN algorithm = 'HS512' THEN 'sha512'
  ELSE '' END AS id)  -- hmac throws error
    SELECT pgjwt.url_encode(hmac(signables, secret, alg.id)) FROM alg;
    $$;


    ALTER FUNCTION pgjwt.algorithm_sign(signables text, secret text, algorithm text) OWNER TO postgres;

    --
    -- Name: sign(json, text, text); Type: FUNCTION; Schema: pgjwt; Owner: postgres
    --

    CREATE FUNCTION sign(payload json, secret text, algorithm text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql
    AS $$
    WITH
    header AS (
      SELECT pgjwt.url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) AS data
    ),
    payload AS (
      SELECT pgjwt.url_encode(convert_to(payload::text, 'utf8')) AS data
    ),
    signables AS (
      SELECT header.data || '.' || payload.data AS data FROM header, payload
    )
    SELECT
    signables.data || '.' ||
    pgjwt.algorithm_sign(signables.data, secret, algorithm) FROM signables;
    $$;


    ALTER FUNCTION pgjwt.sign(payload json, secret text, algorithm text) OWNER TO postgres;

    --
    -- Name: url_decode(text); Type: FUNCTION; Schema: pgjwt; Owner: postgres
    --

    CREATE FUNCTION url_decode(data text) RETURNS bytea
    LANGUAGE sql
    AS $$
    WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
    rem AS (SELECT length(t.trans) % 4 AS remainder FROM t) -- compute padding size
    SELECT decode(
      t.trans ||
      CASE WHEN rem.remainder > 0
        THEN repeat('=', (4 - rem.remainder))
      ELSE '' END,
        'base64') FROM t, rem;
      $$;


      ALTER FUNCTION pgjwt.url_decode(data text) OWNER TO postgres;

      --
      -- Name: url_encode(bytea); Type: FUNCTION; Schema: pgjwt; Owner: postgres
      --

      CREATE FUNCTION url_encode(data bytea) RETURNS text
      LANGUAGE sql
      AS $$
      SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
      $$;


      ALTER FUNCTION pgjwt.url_encode(data bytea) OWNER TO postgres;

      --
      -- Name: verify(text, text, text); Type: FUNCTION; Schema: pgjwt; Owner: postgres
      --

      CREATE FUNCTION verify(token text, secret text, algorithm text DEFAULT 'HS256'::text) RETURNS TABLE(header json, payload json, valid boolean)
      LANGUAGE sql
      AS $$
      SELECT
      convert_from(pgjwt.url_decode(r[1]), 'utf8')::json AS header,
      convert_from(pgjwt.url_decode(r[2]), 'utf8')::json AS payload,
      r[3] = pgjwt.algorithm_sign(r[1] || '.' || r[2], secret, algorithm) AS valid
      FROM regexp_split_to_array(token, '\.') r;
      $$;


      ALTER FUNCTION pgjwt.verify(token text, secret text, algorithm text) OWNER TO postgres;

      SET search_path = postgraphile_watch, pg_catalog;

      --
      -- Name: notify_watchers_ddl(); Type: FUNCTION; Schema: postgraphile_watch; Owner: postgres
      --

      CREATE FUNCTION notify_watchers_ddl() RETURNS event_trigger
      LANGUAGE plpgsql
      AS $$
      begin
        perform pg_notify(
          'postgraphile_watch',
          json_build_object(
            'type',
            'ddl',
            'payload',
            (select json_agg(json_build_object('schema', schema_name, 'command', command_tag)) from pg_event_trigger_ddl_commands() as x)
          )::text
        );
      end;
      $$;


      ALTER FUNCTION postgraphile_watch.notify_watchers_ddl() OWNER TO postgres;

      --
      -- Name: notify_watchers_drop(); Type: FUNCTION; Schema: postgraphile_watch; Owner: postgres
      --

      CREATE FUNCTION notify_watchers_drop() RETURNS event_trigger
      LANGUAGE plpgsql
      AS $$
      begin
        perform pg_notify(
          'postgraphile_watch',
          json_build_object(
            'type',
            'drop',
            'payload',
            (select json_agg(distinct x.schema_name) from pg_event_trigger_dropped_objects() as x)
          )::text
        );
      end;
      $$;


      ALTER FUNCTION postgraphile_watch.notify_watchers_drop() OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: twilio_calls; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE twilio_calls (
        id integer NOT NULL,
        activist_id integer,
        widget_id integer,
        twilio_account_sid text,
        twilio_call_sid text,
        "from" text NOT NULL,
        "to" text NOT NULL,
        data jsonb DEFAULT '{}'::jsonb NOT NULL,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        community_id integer
      );


      ALTER TABLE twilio_calls OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: twilio_calls; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW twilio_calls AS
      SELECT twilio_calls.id,
      twilio_calls.activist_id,
      twilio_calls.widget_id,
      twilio_calls.twilio_account_sid,
      twilio_calls.twilio_call_sid,
      twilio_calls."from",
      twilio_calls."to",
      twilio_calls.data,
      twilio_calls.created_at,
      twilio_calls.updated_at,
      twilio_calls.community_id
      FROM public.twilio_calls;


      ALTER TABLE twilio_calls OWNER TO postgres;

      --
      -- Name: add_twilio_call(twilio_calls); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION add_twilio_call(call twilio_calls) RETURNS twilio_calls
      LANGUAGE plpgsql
      AS $$
      DECLARE twilio_calls postgraphql.twilio_calls;
      BEGIN
        INSERT INTO postgraphql.twilio_calls (
          activist_id,
          community_id,
          widget_id,
          "from",
          "to",
          created_at,
          updated_at
          ) VALUES (
          coalesce(CALL.activist_id, NULL),
          CALL.community_id,
          CALL.widget_id,
          CALL.from,
          CALL.to,
          now(),
          now()
        ) returning * INTO twilio_calls;
        RETURN twilio_calls;
      END;
      $$;


      ALTER FUNCTION postgraphql.add_twilio_call(call twilio_calls) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: twilio_configurations; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE twilio_configurations (
        id integer NOT NULL,
        community_id integer NOT NULL,
        twilio_account_sid text NOT NULL,
        twilio_auth_token text NOT NULL,
        twilio_number text NOT NULL,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL
      );


      ALTER TABLE twilio_configurations OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: twilio_configurations; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW twilio_configurations AS
      SELECT twilio_configurations.id,
      twilio_configurations.community_id,
      twilio_configurations.twilio_account_sid,
      twilio_configurations.twilio_auth_token,
      twilio_configurations.twilio_number,
      twilio_configurations.created_at,
      twilio_configurations.updated_at
      FROM public.twilio_configurations;


      ALTER TABLE twilio_configurations OWNER TO postgres;

      --
      -- Name: add_twilio_configuration(twilio_configurations); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION add_twilio_configuration(config twilio_configurations) RETURNS twilio_configurations
      LANGUAGE plpgsql
      AS $$
      DECLARE twilio_configuration postgraphql.twilio_configurations;
      BEGIN
        INSERT INTO postgraphql.twilio_configurations (
          community_id,
          twilio_account_sid,
          twilio_auth_token,
          twilio_number,
          created_at,
          updated_at
          ) VALUES (
          CONFIG.community_id,
          CONFIG.twilio_account_sid,
          CONFIG.twilio_auth_token,
          CONFIG.twilio_number,
          now(),
          now()
        ) RETURNING * INTO twilio_configuration;
        RETURN twilio_configuration;
      END;
      $$;


      ALTER FUNCTION postgraphql.add_twilio_configuration(config twilio_configurations) OWNER TO postgres;

      --
      -- Name: authenticate(text, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION authenticate(email text, password text) RETURNS jwt_token
      LANGUAGE plpgsql STRICT SECURITY DEFINER
      AS $_$
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
      $_$;


      ALTER FUNCTION postgraphql.authenticate(email text, password text) OWNER TO postgres;

      --
      -- Name: FUNCTION authenticate(email text, password text); Type: COMMENT; Schema: postgraphql; Owner: postgres
      --

      COMMENT ON FUNCTION authenticate(email text, password text) IS 'Creates a JWT token that will securely identify a user and give them certain permissions.';


      --
      -- Name: change_password(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION change_password(data json) RETURNS jwt_token
      LANGUAGE plpgsql
      AS $_$
      declare
      _user public.users;
      begin
        if nullif(($1->> 'password')::text, '') is null then
          raise 'missing_password';
        end if;

        if length(($1->>'password'::text)) < 6 then
          raise 'password_lt_six_chars';
        end if;

        if ($1->>'password'::text) <> ($1->>'password_confirmation'::text) then
          raise 'password_confirmation_not_match';
        end if;

        -- when user is anonymous should be have reset_password_token
        if current_role = 'anonymous' then
          if nullif(($1->>'reset_password_token')::text, '') is not null then
            select * from public.users 
            where reset_password_token is not null
            and ($1->>'reset_password_token')::text = reset_password_token
            into _user;

            if _user.id is null then
              raise 'invalid_reset_password_token';
            end if;
          else
            raise 'missing_reset_password_token';
          end if;
        else
          -- when user already logged (jwt) should not require reset_password_token
          select * from users where id = postgraphql.current_user_id()
          into _user;
        end if;

        update users
        set encrypted_password = public.crypt(($1->>'password')::text, public.gen_salt('bf', 9))
        where id = _user.id;

        return (
          (case when _user.admin is true then 'admin' else 'common_user' end), 
          _user.id
        )::postgraphql.jwt_token;        
      end;
      $_$;


      ALTER FUNCTION postgraphql.change_password(data json) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: invitations; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE invitations (
        id integer NOT NULL,
        community_id integer,
        user_id integer,
        email character varying,
        code character varying,
        expires timestamp without time zone,
        role integer,
        expired boolean,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL
      );


      ALTER TABLE invitations OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: check_invitation(text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION check_invitation(invitation_code text) RETURNS SETOF public.invitations
      LANGUAGE sql IMMUTABLE
      AS $$
      select * from public.invitations where code=invitation_code
      $$;


      ALTER FUNCTION postgraphql.check_invitation(invitation_code text) OWNER TO postgres;

      --
      -- Name: create_activist(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_activist(activist json) RETURNS json
      LANGUAGE plpgsql
      AS $_$
      declare
      _activist public.activists;
      _community_id integer;
      _mobilization public.mobilizations;
      _community_activist public.community_activists;
      begin
        _community_id := ($1->>'community_id')::integer;

        if _community_id is null then
          raise 'missing community_id inside activist';
        end if;            

        if not postgraphql.current_user_has_community_participation(_community_id) then
          raise 'operation not permitted';
        end if;

        select * from public.mobilizations
        where community_id = _community_id
        and id = ($1->>'mobilization_id')::integer
        into _mobilization;

        select * from public.activists a
        where a.email = lower(($1->>'email')::email)
        limit 1 into _activist;

        if _activist.id is null then 
          insert into public.activists (first_name, last_name, name, email, phone, document_number, document_type, city, created_at, updated_at)
          values ($1->>'first_name'::text, $1->>'last_name'::text, $1->>'name'::text, lower($1->>'email'), $1->>'phone'::text, $1->>'document_number'::text,
            $1->>'document_type'::text, $1->>'city'::text, now(), now())
          returning * into _activist;
        end if;

        select *
        from public.community_activists 
        where community_id = _community_id 
        and activist_id = _activist.id
        into _community_activist;

        if _community_activist.id is null then
          insert into public.community_activists (community_id, activist_id, created_at, updated_at, profile_data)
          values (_community_id, _activist.id, now(), now(), ($1)::jsonb)
          returning * into _community_activist;
        end if;

        if _mobilization.id is not null and not exists(select true 
          from public.mobilization_activists 
          where mobilization_id = _mobilization.id
          and activist_id = _activist.id
          ) then
          insert into public.mobilization_activists (mobilization_id, activist_id, created_at, updated_at)
          values (_mobilization.id, _activist.id, now(), now());
        end if;            

        return row_to_json(_community_activist);
      end;
      $_$;


      ALTER FUNCTION postgraphql.create_activist(activist json) OWNER TO postgres;

      --
      -- Name: create_activist_tag(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_activist_tag(data json) RETURNS json
      LANGUAGE plpgsql
      AS $_$
      declare
      _activist public.activists;
      _tagging public.taggings;
      _tag public.tags;
      _activist_tag public.activist_tags;
      _community_id integer;
      --_mobilization public.mobilizations;            
      begin
        -- check for community_id
        _community_id := ($1->>'community_id')::integer;
        if _community_id is null then
          raise 'missing community_id inside activist';
        end if;            

        -- check if current_user has participation on this community or he is admin
        if not postgraphql.current_user_has_community_participation(_community_id) and current_role <> 'admin' then
          raise 'operation not permitted';
        end if;

        -- get mobilization
        -- select * from public.mobilizations
        --     where community_id = _community_id
        --         and id = ($1->>'mobilization_id')::integer
        --     into _mobilization;

        -- get activist
        select * from public.activists a
        where a.id = ($1->>'activist_id')::integer
        limit 1 into _activist;

        -- check if activists in community
        if not exists(select true from community_activists 
          where community_id = _community_id
          and activist_id = _activist.id) then
          raise 'activist not found on community';
        end if;

        -- insert new activist_tag
        select * from public.activist_tags 
        where activist_id = _activist.id 
        and community_id = _community_id
        into _activist_tag;

        if _activist_tag is null then
          insert into public.activist_tags (activist_id, community_id, created_at, updated_at)
          values (_activist.id, _community_id, now(), now())
          returning * into _activist_tag;
        end if;

        -- search for some tag that have the same name
        select * from public.tags
        where name = 'input_'||public.slugfy(($1->>'name')::text)
        limit 1
        into _tag;

        -- insert tag if not found
        if _tag is null then
          insert into public.tags (name, label) 
          values ('input_'||public.slugfy(($1->>'name')::text), ($1->>'name')::text)
          returning * into _tag;
        end if;

        -- create taggings linking activist_tag to tag
        select * from public.taggings
        where tag_id = _tag.id
        and taggable_id = _activist_tag.id
        and taggable_type = 'ActivistTag'
        into _tagging;
        if _tagging is null then
          insert into public.taggings(tag_id, taggable_id, taggable_type) 
          values (_tag.id, _activist_tag.id, 'ActivistTag')
          returning * into _tagging;
        end if;

        return json_build_object(
          'activist_tag_id', _activist_tag.id,
          'tag_id', _tag.id,
          'activist_id', _activist.id,
          'tag_name', _tag.name,
          'tag_label', _tag.label
        );
      end;
      $_$;


      ALTER FUNCTION postgraphql.create_activist_tag(data json) OWNER TO postgres;

      --
      -- Name: create_bot(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_bot(bot_data json) RETURNS json
      LANGUAGE plpgsql
      AS $$
      declare
      bot_json public.facebook_bot_configurations;
      begin
        insert into public.facebook_bot_configurations
        (community_id, messenger_app_secret, messenger_validation_token, messenger_page_access_token, data, created_at, updated_at)
        values (
          (bot_data ->> 'community_id')::integer,
          (bot_data ->> 'messenger_app_secret'),
          (bot_data ->> 'messenger_validation_token'),
          (bot_data ->> 'messenger_page_access_token'),
          coalesce((bot_data ->> 'data')::jsonb, '{}'),
          now(),
          now())
        returning * into bot_json;

        return row_to_json(bot_json);
      end;
      $$;


      ALTER FUNCTION postgraphql.create_bot(bot_data json) OWNER TO postgres;

      --
      -- Name: create_bot_interaction(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_bot_interaction(bot_data json) RETURNS json
      LANGUAGE plpgsql
      AS $$
      declare
      bot_json public.activist_facebook_bot_interactions;
      begin
        insert into public.activist_facebook_bot_interactions
        (facebook_bot_configuration_id, fb_context_recipient_id, fb_context_sender_id, interaction, created_at, updated_at)
        values (
          (bot_data ->> 'facebook_bot_configuration_id')::integer,
          (bot_data ->> 'fb_context_recipient_id'),
          (bot_data ->> 'fb_context_sender_id'),
          coalesce((bot_data ->> 'interaction')::jsonb, '{}'),
          now(),
          now())
        returning * into bot_json;

        return row_to_json(bot_json);
      end;
      $$;


      ALTER FUNCTION postgraphql.create_bot_interaction(bot_data json) OWNER TO postgres;

      --
      -- Name: create_community(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_community(data json) RETURNS json
      LANGUAGE plpgsql
      AS $_$
      declare
      _community public.communities;
      begin
        if current_role = 'anonymous' then
          raise 'permission_denied';
        end if;

        if nullif(btrim($1->> 'name'::text), '') is null then
          raise 'missing_community_name';
        end if;

        if nullif(btrim($1->> 'city'::text), '') is null then
          raise 'missing_community_city';
        end if;

        insert into public.communities(name, city, created_at, updated_at)
        values(
          ($1->>'name')::text,
          ($1->>'city')::text,
          now(),
          now()
        ) returning * into _community;

        -- create user x community after create community
        insert into public.community_users(user_id, community_id, role, created_at, updated_at)
        values(
          postgraphql.current_user_id(),
          _community.id,
          1,
          now(),
          now()
        );

        return row_to_json(_community);
      end;
      $_$;


      ALTER FUNCTION postgraphql.create_community(data json) OWNER TO postgres;

      --
      -- Name: create_dns_record(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_dns_record(data json) RETURNS json
      LANGUAGE plpgsql
      AS $_$
      declare
      _dns_hosted_zone public.dns_hosted_zones;
      _dns_record public.dns_records;
      begin
        -- to execute function in api-v1
        -- if current_role <> 'microservices' then
        --     raise 'permission_denied';
        -- end if;

        select * from public.dns_hosted_zones d where d.id = ($1->>'dns_hosted_zone_id')::integer
        into _dns_hosted_zone;

        if _dns_hosted_zone is null then
          raise 'dns_hosted_zone_not_found';
        end if;

        select *
        from public.dns_records
        where name = $1->>'name' and record_type = $1->>'record_type'
        into _dns_record;

        if _dns_record is null then
          insert into public.dns_records(dns_hosted_zone_id, name, record_type, value, ttl, created_at, updated_at, comment)
          values (
            _dns_hosted_zone.id, $1->>'name', $1->>'record_type', $1->>'value', $1->>'ttl', now(), now(),  $1->>'comment'
          )
          returning * into _dns_record;

          -- after create dns_record perform route53
          perform pg_notify('dns_channel', pgjwt.sign(json_build_object(
                'action', 'create_dns_record',
                'id', _dns_record.id,
                'created_at', _dns_record.created_at,
                'sent_to_queuing', now(),
                'jit', now()::timestamp
          ), public.configuration('jwt_secret'), 'HS512'));

      return json_build_object(
        'id', _dns_record.id,
        'dns_hosted_zone_id', _dns_record.dns_hosted_zone_id,
        'name', _dns_record.name,
        'comment', _dns_record.comment
      );
    else
      raise 'dns_record_already_registered';
        end if;
      end;
      $_$;


      ALTER FUNCTION postgraphql.create_dns_record(data json) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: facebook_bot_campaigns; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE facebook_bot_campaigns (
        id integer NOT NULL,
        facebook_bot_configuration_id integer NOT NULL,
        name text NOT NULL,
        segment_filters jsonb NOT NULL,
        total_impacted_activists integer NOT NULL,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL
      );


      ALTER TABLE facebook_bot_campaigns OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: create_facebook_bot_campaign(facebook_bot_campaigns_type); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_facebook_bot_campaign(campaign facebook_bot_campaigns_type) RETURNS public.facebook_bot_campaigns
      LANGUAGE plpgsql
      AS $$
      DECLARE
      _facebook_bot_campaign public.facebook_bot_campaigns;
      _campaign_id integer;
      BEGIN
        INSERT INTO public.facebook_bot_campaigns (
          facebook_bot_configuration_id,
          name,
          segment_filters,
          total_impacted_activists,
          created_at,
          updated_at
          ) VALUES (
          campaign.facebook_bot_configuration_id,
          campaign.name,
          campaign.segment_filters,
          campaign.total_impacted_activists,
          now(),
          now()
        ) RETURNING * INTO _facebook_bot_campaign;

        INSERT INTO public.facebook_bot_campaign_activists (
          facebook_bot_campaign_id,
          facebook_bot_activist_id,
          received,
          created_at,
          updated_at
        )
        SELECT
        (to_json(_facebook_bot_campaign) ->> 'id')::integer as facebook_bot_activist_id,
        id as facebook_bot_activist_id,
        FALSE,
        NOW(),
        NOW()
        FROM postgraphql.get_facebook_bot_activists_strategy(campaign.segment_filters);
        RETURN _facebook_bot_campaign;
      END;
      $$;


      ALTER FUNCTION postgraphql.create_facebook_bot_campaign(campaign facebook_bot_campaigns_type) OWNER TO postgres;

      --
      -- Name: create_tags(text, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_tags(name text, label text) RETURNS json
      LANGUAGE plpgsql
      AS $$
      declare
      _tag public.tags;
      _user_tag public.user_tags;
      begin
        if current_role = 'anonymous' then
          raise 'permission_denied';
        end if;

        if name is null then
          raise 'name_is_empty';
        end if;

        if label is null then
          raise 'label_is_empty';
        end if;

        insert into public.tags(name, label)
        values(concat('user_', name), label)
        returning * into _tag;

        -- insert a new tag in current_user
        insert into public.user_tags(user_id, tag_id, created_at, updated_at)
        values(postgraphql.current_user_id(), _tag.id, now(), now())
        returning * into _user_tag;

        return json_build_object(
          'msg', 'tag created successful',
          'tag_id', _tag.id,
          'user_tag', _user_tag.id
        );
      end;
      $$;


      ALTER FUNCTION postgraphql.create_tags(name text, label text) OWNER TO postgres;

      --
      -- Name: create_user_tags(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION create_user_tags(data json) RETURNS json
      LANGUAGE plpgsql
      AS $_$
      declare
      _tags json;
      _tag text;
      begin
        if current_role = 'anonymous' then
          raise 'permission_denied';
        end if;

        for _tag in (select * from json_array_elements_text(($1->>'tags')::json))
          loop
            insert into public.user_tags(user_id, tag_id, created_at, updated_at)
            (
              select postgraphql.current_user_id(),
              (select id from public.tags where name = _tag),
              now(),
              now()
            ) returning * into _tags;
          end loop;

          return (select json_agg(t.name) from (
              select * from tags t
              left join user_tags ut on ut.tag_id = t.id
              where ut.user_id = (postgraphql.current_user_id())
          ) t);
        end;
        $_$;


        ALTER FUNCTION postgraphql.create_user_tags(data json) OWNER TO postgres;

        --
        -- Name: users; Type: VIEW; Schema: postgraphql; Owner: postgres
        --

        CREATE VIEW users AS
        SELECT
        NULL::integer AS id,
        NULL::character varying AS provider,
        NULL::character varying AS uid,
        NULL::character varying AS encrypted_password,
        NULL::character varying AS reset_password_token,
        NULL::timestamp without time zone AS reset_password_sent_at,
        NULL::timestamp without time zone AS remember_created_at,
        NULL::integer AS sign_in_count,
        NULL::timestamp without time zone AS current_sign_in_at,
        NULL::timestamp without time zone AS last_sign_in_at,
        NULL::character varying AS current_sign_in_ip,
        NULL::character varying AS last_sign_in_ip,
        NULL::character varying AS confirmation_token,
        NULL::timestamp without time zone AS confirmed_at,
        NULL::timestamp without time zone AS confirmation_sent_at,
        NULL::character varying AS unconfirmed_email,
        NULL::character varying AS first_name,
        NULL::character varying AS last_name,
        NULL::character varying AS email,
        NULL::text AS tokens,
        NULL::timestamp without time zone AS created_at,
        NULL::timestamp without time zone AS updated_at,
        NULL::character varying AS avatar,
        NULL::boolean AS admin,
        NULL::text AS locale,
        NULL::json AS tags;


        ALTER TABLE users OWNER TO postgres;

        --
        -- Name: current_user(); Type: FUNCTION; Schema: postgraphql; Owner: postgres
        --

        CREATE FUNCTION "current_user"() RETURNS users
        LANGUAGE sql STABLE
        AS $$
        select *
        from postgraphql.users
        where id = current_setting('jwt.claims.user_id')::integer
        $$;


        ALTER FUNCTION postgraphql."current_user"() OWNER TO postgres;

        --
        -- Name: current_user_has_community_participation(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
        --

        CREATE FUNCTION current_user_has_community_participation(com_id integer) RETURNS boolean
        LANGUAGE sql
        AS $$
        select (exists(
            select true from public.community_users cu
            where cu.user_id = postgraphql.current_user_id()
            and cu.community_id = com_id
        ) or current_role = 'admin');
      $$;


      ALTER FUNCTION postgraphql.current_user_has_community_participation(com_id integer) OWNER TO postgres;

      --
      -- Name: current_user_has_community_participation(integer, integer[]); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION current_user_has_community_participation(com_id integer, role_ids integer[]) RETURNS boolean
      LANGUAGE sql
      AS $$
      select exists(
        select true from public.community_users cu
        where cu.user_id = postgraphql.current_user_id()
        and cu.community_id = com_id
        and cu.role = ANY(role_ids)
      );
      $$;


      ALTER FUNCTION postgraphql.current_user_has_community_participation(com_id integer, role_ids integer[]) OWNER TO postgres;

      --
      -- Name: current_user_id(); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION current_user_id() RETURNS integer
      LANGUAGE sql
      AS $$
      select id from postgraphql.current_user();
      $$;


      ALTER FUNCTION postgraphql.current_user_id() OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: template_mobilizations; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE template_mobilizations (
        id integer NOT NULL,
        name character varying,
        user_id integer,
        color_scheme character varying,
        facebook_share_title character varying,
        facebook_share_description text,
        header_font character varying,
        body_font character varying,
        facebook_share_image character varying,
        slug character varying NOT NULL,
        custom_domain character varying,
        twitter_share_text character varying(140),
        community_id integer,
        uses_number integer,
        global boolean,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        goal text
      );


      ALTER TABLE template_mobilizations OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: custom_templates(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION custom_templates(ctx_community_id integer) RETURNS SETOF public.template_mobilizations
      LANGUAGE sql STABLE
      AS $$
      select *
      from public.template_mobilizations
      where community_id = ctx_community_id
      and global = false
      and postgraphql.current_user_has_community_participation(ctx_community_id);
      $$;


      ALTER FUNCTION postgraphql.custom_templates(ctx_community_id integer) OWNER TO postgres;

      --
      -- Name: destroy_bot(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION destroy_bot(bot_id integer) RETURNS void
      LANGUAGE sql
      AS $$
      update public.facebook_bot_configurations
      set data = jsonb_set(data, '{deleted}', 'true')
      where id = bot_id
      $$;


      ALTER FUNCTION postgraphql.destroy_bot(bot_id integer) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: activist_tags; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE activist_tags (
        id integer NOT NULL,
        activist_id integer,
        community_id integer,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        mobilization_id integer
      );


      ALTER TABLE activist_tags OWNER TO postgres;

      --
      -- Name: taggings; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE taggings (
        id integer NOT NULL,
        tag_id integer,
        taggable_id integer,
        taggable_type character varying,
        tagger_id integer,
        tagger_type character varying,
        context character varying(128),
        created_at timestamp without time zone
      );


      ALTER TABLE taggings OWNER TO postgres;

      --
      -- Name: tags; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE tags (
        id integer NOT NULL,
        name character varying,
        taggings_count integer DEFAULT 0,
        label text
      );


      ALTER TABLE tags OWNER TO postgres;

      --
      -- Name: community_tags; Type: VIEW; Schema: public; Owner: postgres
      --

      CREATE VIEW community_tags AS
      SELECT at.community_id,
      tag.name AS tag_complete_name,
      (regexp_split_to_array((tag.name)::text, '_'::text))[1] AS tag_from,
      (regexp_split_to_array((tag.name)::text, '_'::text))[2] AS tag_name,
      count(DISTINCT at.activist_id) AS total_activists,
      tag.label AS tag_label
      FROM ((activist_tags at
          JOIN taggings tgs ON ((((tgs.taggable_type)::text = 'ActivistTag'::text) AND (tgs.taggable_id = at.id))))
        JOIN tags tag ON ((tag.id = tgs.tag_id)))
      GROUP BY at.community_id, tag.name, tag.label;


      ALTER TABLE community_tags OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: community_tags; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW community_tags AS
      SELECT community_tags.community_id,
      community_tags.tag_complete_name,
      community_tags.tag_from,
      community_tags.tag_name,
      community_tags.total_activists,
      community_tags.tag_label
      FROM public.community_tags
      WHERE current_user_has_community_participation(community_tags.community_id);


      ALTER TABLE community_tags OWNER TO postgres;

      --
      -- Name: filter_community_tags(text, integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION filter_community_tags(search text, ctx_community_id integer) RETURNS SETOF community_tags
      LANGUAGE sql STABLE
      AS $$
      select * from postgraphql.community_tags
      where community_id = ctx_community_id
      and tag_complete_name ilike ('%' || search || '%')
      $$;


      ALTER FUNCTION postgraphql.filter_community_tags(search text, ctx_community_id integer) OWNER TO postgres;

      --
      -- Name: FUNCTION filter_community_tags(search text, ctx_community_id integer); Type: COMMENT; Schema: postgraphql; Owner: postgres
      --

      COMMENT ON FUNCTION filter_community_tags(search text, ctx_community_id integer) IS 'filter community_tags view by tag_complete_name and communityd_id';


      --
      -- Name: get_facebook_activists_by_campaign_ids(integer[]); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_campaign_ids(campaign_ids integer[]) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      DISTINCT _fba.fb_context_recipient_id,
      _fba.fb_context_sender_id,
      _fba.data,
      _fba.messages,
      _fba.quick_replies,
      _fba.created_at,
      _fba.updated_at,
      _fba.id
      FROM public.facebook_bot_campaign_activists as _fbca
      LEFT JOIN public.facebook_bot_activists as _fba
      ON _fba.id = _fbca.facebook_bot_activist_id
      WHERE _fbca.facebook_bot_campaign_id = ANY(campaign_ids)
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_campaign_ids(campaign_ids integer[]) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_campaigns_both_inclusion_exclusion(jsonb, integer[], integer[]); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_campaigns_both_inclusion_exclusion(segment_filters jsonb, campaign_exclusion_ids integer[], campaign_inclusion_ids integer[]) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT *
      FROM postgraphql.get_facebook_activists_by_campaigns_exclusion(
        segment_filters,
        campaign_exclusion_ids
      )
      UNION
      SELECT *
      FROM postgraphql.get_facebook_activists_by_campaign_ids(
        campaign_inclusion_ids
      );
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_campaigns_both_inclusion_exclusion(segment_filters jsonb, campaign_exclusion_ids integer[], campaign_inclusion_ids integer[]) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_campaigns_exclusion(jsonb, integer[]); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_campaigns_exclusion(segment_filters jsonb, campaign_ids integer[]) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fas.fb_context_recipient_id,
      fas.fb_context_sender_id,
      fas.data,
      fas.messages,
      fas.quick_replies,
      fas.created_at,
      fas.updated_at,
      fas.id
      FROM postgraphql.get_facebook_bot_activists_strategy(segment_filters) as fas
      LEFT JOIN (
        SELECT fba.*
        FROM public.facebook_bot_campaign_activists as fbca
        LEFT JOIN public.facebook_bot_activists as fba
        ON fba.id = fbca.facebook_bot_activist_id
        WHERE fbca.facebook_bot_campaign_id = ANY(campaign_ids)
      ) as fbca
      ON fbca.fb_context_recipient_id = fas.fb_context_recipient_id
      WHERE fbca.id IS NULL
      ORDER BY fas.updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_campaigns_exclusion(segment_filters jsonb, campaign_ids integer[]) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_campaigns_inclusion(jsonb, integer[]); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_campaigns_inclusion(segment_filters jsonb, campaign_ids integer[]) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fas.fb_context_recipient_id,
      fas.fb_context_sender_id,
      fas.data,
      fas.messages,
      fas.quick_replies,
      fas.created_at,
      fas.updated_at,
      fas.id
      FROM postgraphql.get_facebook_bot_activists_strategy(segment_filters) as fas
      UNION
      SELECT *
      FROM postgraphql.get_facebook_activists_by_campaign_ids(campaign_ids);
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_campaigns_inclusion(segment_filters jsonb, campaign_ids integer[]) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_date_interval(timestamp without time zone, timestamp without time zone); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_date_interval(date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT DISTINCT
      fb_context_recipient_id,
      fb_context_sender_id,
      data,
      messages,
      quick_replies,
      created_at,
      updated_at,
      id
      FROM (
        SELECT *, UNNEST(interaction_dates) as interaction_date
        FROM public.facebook_bot_activists
      ) as a
      WHERE interaction_date::date BETWEEN date_interval_start AND date_interval_end
      ORDER BY updated_at;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_date_interval(date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_message(text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_message(message text) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fb_context_recipient_id,
      fb_context_sender_id,
      data,
      messages,
      quick_replies,
      created_at,
      updated_at,
      id
      FROM public.facebook_bot_activists
      WHERE messages @@ plainto_tsquery('portuguese', message)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_message(message text) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_message_date_interval(text, timestamp without time zone, timestamp without time zone); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_message_date_interval(message text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT *
      FROM postgraphql.get_facebook_activists_by_date_interval(
        date_interval_start,
        date_interval_end
      )
      WHERE messages @@ plainto_tsquery('portuguese', message)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_message_date_interval(message text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_message_quick_reply(text, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_message_quick_reply(message text, quick_reply text) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fb_context_recipient_id,
      fb_context_sender_id,
      data,
      messages,
      quick_replies,
      created_at,
      updated_at,
      id
      FROM public.facebook_bot_activists
      WHERE
      messages @@ plainto_tsquery('portuguese', message) AND
      quick_reply = ANY(quick_replies)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_message_quick_reply(message text, quick_reply text) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_message_quick_reply_date_interval(text, text, timestamp without time zone, timestamp without time zone); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_message_quick_reply_date_interval(message text, quick_reply text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT *
      FROM postgraphql.get_facebook_activists_by_date_interval(
        date_interval_start,
        date_interval_end
      )
      WHERE
      messages @@ plainto_tsquery('portuguese', message) AND
      quick_reply = ANY(quick_replies)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_message_quick_reply_date_interval(message text, quick_reply text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_quick_reply(text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_quick_reply(quick_reply text) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fb_context_recipient_id,
      fb_context_sender_id,
      data,
      messages,
      quick_replies,
      created_at,
      updated_at,
      id
      FROM public.facebook_bot_activists
      WHERE quick_reply = ANY(quick_replies)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_quick_reply(quick_reply text) OWNER TO postgres;

      --
      -- Name: get_facebook_activists_by_quick_reply_date_interval(text, timestamp without time zone, timestamp without time zone); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_activists_by_quick_reply_date_interval(quick_reply text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT *
      FROM postgraphql.get_facebook_activists_by_date_interval(
        date_interval_start,
        date_interval_end
      )
      WHERE quick_reply = ANY(quick_replies)
      ORDER BY updated_at DESC;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_activists_by_quick_reply_date_interval(quick_reply text, date_interval_start timestamp without time zone, date_interval_end timestamp without time zone) OWNER TO postgres;

      --
      -- Name: get_facebook_bot_activists_strategy(jsonb); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_bot_activists_strategy(search jsonb) RETURNS SETOF facebook_activist_search_result_type
      LANGUAGE plpgsql IMMUTABLE
      AS $$
      DECLARE
      _message                text      := search ->> 'message';
      _quick_reply            text      := search ->> 'quickReply';
      _date_interval_start    timestamp := search ->> 'dateIntervalStart';
      _date_interval_end      timestamp := search ->> 'dateIntervalEnd';
      _campaign_exclusion_ids int[]     := search ->> 'campaignExclusionIds';
      _campaign_inclusion_ids int[]     := search ->> 'campaignInclusionIds';

      _m      boolean := _message                IS NOT NULL;
      _qr     boolean := _quick_reply            IS NOT NULL;
      _start  boolean := _date_interval_start    IS NOT NULL;
      _end    boolean := _date_interval_end      IS NOT NULL;
      _ce     boolean := _campaign_exclusion_ids IS NOT NULL;
      _ci     boolean := _campaign_inclusion_ids IS NOT NULL;

      _is_only_campaign_exclusion boolean :=      _ce  AND (NOT _ci);
      _is_only_campaign_inclusion boolean := (NOT _ce) AND      _ci;
      _is_both_campaign_strategy  boolean :=      _ce  AND      _ci;
      _is_only_message            boolean :=      _m  AND (NOT _qr) AND (NOT _start) AND (NOT _end);
      _is_only_q_reply            boolean := (NOT _m) AND      _qr  AND (NOT _start) AND (NOT _end);
      _is_only_date_interval      boolean := (NOT _m) AND (NOT _qr) AND      _start  AND      _end;
      _is_q_reply_date_interval   boolean := (NOT _m) AND      _qr  AND       _start AND      _end;
      _is_message_date_interval   boolean :=      _m  AND (NOT _qr) AND      _start  AND      _end;
      _is_message_q_reply         boolean :=      _m  AND      _qr  AND (NOT _start) AND (NOT _end);
      _is_all                     boolean :=      _m  AND      _qr  AND      _start  AND      _end;
      BEGIN
        IF _is_only_campaign_exclusion THEN RETURN QUERY (
          SELECT *
          FROM postgraphql.get_facebook_activists_by_campaigns_exclusion(
            search - 'campaignExclusionIds',
            _campaign_exclusion_ids
          )
          );
        ELSIF _is_only_campaign_inclusion THEN RETURN QUERY (
          SELECT *
          FROM postgraphql.get_facebook_activists_by_campaigns_inclusion(
            search - 'campaignInclusionIds',
            _campaign_inclusion_ids
          )
          );
        ELSIF _is_both_campaign_strategy THEN RETURN QUERY (
          SELECT *
          FROM postgraphql.get_facebook_activists_by_campaigns_both_inclusion_exclusion(
            search - 'campaignInclusionIds' - 'campaignExclusionIds',
            _campaign_exclusion_ids,
            _campaign_inclusion_ids
          )
          );
        ELSE
          IF _is_only_message THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_message(_message)
            );
          ELSIF _is_only_q_reply THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_quick_reply(_quick_reply)
            );
          ELSIF _is_only_date_interval THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_date_interval(
              _date_interval_start,
              _date_interval_end
            )
            );
          ELSIF _is_q_reply_date_interval THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_quick_reply_date_interval(
              _quick_reply,
              _date_interval_start,
              _date_interval_end
            )
            );
          ELSIF _is_message_date_interval THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_message_date_interval(
              _message,
              _date_interval_start,
              _date_interval_end
            )
            );
          ELSIF _is_message_q_reply THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_message_quick_reply(
              _message,
              _quick_reply
            )
            );
          ELSIF _is_all THEN RETURN QUERY (
            SELECT *
            FROM postgraphql.get_facebook_activists_by_message_quick_reply_date_interval(
              _message,
              _quick_reply,
              _date_interval_start,
              _date_interval_end
            )
            );
          END IF;
        END IF;
      END;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_bot_activists_strategy(search jsonb) OWNER TO postgres;

      --
      -- Name: get_facebook_bot_campaign_activists_by_campaign_id(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_bot_campaign_activists_by_campaign_id(campaign_id integer) RETURNS SETOF get_facebook_bot_campaign_activists_by_campaign_type
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT
      fbca.*,
      fba.fb_context_recipient_id,
      fba.fb_context_sender_id,
      fba.data,
      fba.messages,
      fba.quick_replies,
      fba.interaction_dates
      FROM public.facebook_bot_campaign_activists as fbca
      LEFT JOIN public.facebook_bot_activists as fba
      ON fba.id = fbca.facebook_bot_activist_id
      WHERE fbca.facebook_bot_campaign_id = campaign_id;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_bot_campaign_activists_by_campaign_id(campaign_id integer) OWNER TO postgres;

      --
      -- Name: get_facebook_bot_campaigns_by_community_id(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_facebook_bot_campaigns_by_community_id(ctx_community_id integer) RETURNS SETOF public.facebook_bot_campaigns
      LANGUAGE sql IMMUTABLE
      AS $$
      SELECT campaigns.*
      FROM public.facebook_bot_campaigns as campaigns
      LEFT JOIN public.facebook_bot_configurations as configs
      ON campaigns.facebook_bot_configuration_id = configs.id
      WHERE configs.community_id = ctx_community_id;
      $$;


      ALTER FUNCTION postgraphql.get_facebook_bot_campaigns_by_community_id(ctx_community_id integer) OWNER TO postgres;

      --
      -- Name: get_widget_donation_stats(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION get_widget_donation_stats(widget_id integer) RETURNS json
      LANGUAGE sql STABLE
      AS $_$
      select
      json_build_object(
        'pledged', sum(d.amount / 100),
        'widget_id', w.id,
        'goal', w.goal,
        'progress', (sum(d.amount / 100) / w.goal) * 100,
        'total_donations', (count(distinct d.id)),
        'total_donators', (count(distinct d.activist_id))
      )
      from widgets w
      join donations d on d.widget_id = w.id
      where w.id = $1 and
      d.transaction_status = 'paid'
      group by w.id;
      $_$;


      ALTER FUNCTION postgraphql.get_widget_donation_stats(widget_id integer) OWNER TO postgres;

      --
      -- Name: FUNCTION get_widget_donation_stats(widget_id integer); Type: COMMENT; Schema: postgraphql; Owner: postgres
      --

      COMMENT ON FUNCTION get_widget_donation_stats(widget_id integer) IS 'Returns a json with pledged, progress and goal from widget';


      --
      -- Name: global_templates(); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION global_templates() RETURNS SETOF public.template_mobilizations
      LANGUAGE sql STABLE
      AS $$
      select *
      from public.template_mobilizations
      where
      global = true
      $$;


      ALTER FUNCTION postgraphql.global_templates() OWNER TO postgres;

      --
      -- Name: mobilizations(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION mobilizations(days integer) RETURNS json
      LANGUAGE plpgsql
      AS $$
      DECLARE
      _result json;
      BEGIN
        if current_role = 'anonymous' then
          raise 'permission_denied';
        end if;

        select json_agg(row_to_json(t.*)) from (select
          c.name as community_name,
          m.name,
          m.goal,
          m.facebook_share_image,
          m.created_at::timestamp as created_at,
          m.updated_at::timestamp as updated_at,
          count(m.id) as score
          -- m.*
          from
          activist_actions aa
          left join mobilizations m on aa.mobilization_id = m.id
          left join communities c on m.community_id = c.id
          where
          -- aa.action_created_date >= now()::date - interval '90days'
          aa.action_created_date >= now()::date - (days || 'days')::interval
          group by
          m.id,
          c.name
          order by
          score desc
        ) t
        into _result;

        return _result;
      END
      $$;


      ALTER FUNCTION postgraphql.mobilizations(days integer) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: communities; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE communities (
        id integer NOT NULL,
        name character varying,
        city character varying,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        mailchimp_api_key text,
        mailchimp_list_id text,
        mailchimp_group_id text,
        image character varying,
        description text,
        recipient_id integer,
        facebook_app_id character varying,
        fb_link character varying,
        twitter_link character varying,
        subscription_retry_interval integer DEFAULT 7,
        subscription_dead_days_interval integer DEFAULT 90,
        email_template_from character varying,
        mailchimp_sync_request_at timestamp without time zone
      );


      ALTER TABLE communities OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: communities; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW communities AS
      SELECT com.id,
      com.name,
      com.city,
      com.description,
      com.created_at,
      com.updated_at,
      com.image,
      com.fb_link,
      com.twitter_link
      FROM public.communities com;


      ALTER TABLE communities OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: mobilizations; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE mobilizations (
        id integer NOT NULL,
        name character varying,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        user_id integer,
        color_scheme character varying,
        google_analytics_code character varying,
        goal text,
        header_font character varying,
        body_font character varying,
        facebook_share_title character varying,
        facebook_share_description text,
        facebook_share_image character varying,
        slug character varying,
        custom_domain character varying,
        twitter_share_text character varying(140),
        community_id integer,
        favicon character varying,
        deleted_at timestamp without time zone,
        status status_mobilization DEFAULT 'active'::status_mobilization,
        traefik_host_rule character varying,
        traefik_backend_address character varying
      );


      ALTER TABLE mobilizations OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: mobilizations; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW mobilizations AS
      SELECT m.id,
      m.name,
      m.created_at,
      m.updated_at,
      m.user_id,
      m.color_scheme,
      m.google_analytics_code,
      m.goal,
      m.header_font,
      m.body_font,
      m.facebook_share_title,
      m.facebook_share_description,
      m.facebook_share_image,
      m.slug,
      m.custom_domain,
      m.twitter_share_text,
      m.community_id,
      m.favicon,
      m.deleted_at,
      m.status
      FROM public.mobilizations m
      WHERE (m.deleted_at IS NULL);


      ALTER TABLE mobilizations OWNER TO postgres;

      --
      -- Name: mobilizations_community(mobilizations); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION mobilizations_community(m mobilizations) RETURNS communities
      LANGUAGE sql STABLE
      AS $$
      select c.*
      from postgraphql.communities c
      where c.id = m.community_id
      $$;


      ALTER FUNCTION postgraphql.mobilizations_community(m mobilizations) OWNER TO postgres;

      --
      -- Name: register(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION register(data json) RETURNS jwt_token
      LANGUAGE plpgsql
      AS $_$
      declare
      _user public.users;
      _invitation public.invitations;
      begin
        if current_role <> 'anonymous' then
          raise 'user_already_logged';
        end if;
        -- check if first_name, email and password are present
        if nullif(btrim($1->> 'first_name'::text), '') is null then
          raise 'missing_first_name';
        end if;

        if nullif(btrim($1->> 'email'::text), '') is null then
          raise 'missing_email';
        end if;

        if nullif(($1->> 'password')::text, '') is null then
          raise 'missing_password';
        end if;

        if length(($1->>'password'::text)) < 6 then
          raise 'password_lt_six_chars';
        end if;

        insert into public.users(uid, provider, email, encrypted_password, first_name, last_name)
        values (
          ($1->>'email')::email, 
          'email', 
          ($1->>'email')::email, 
          crypt($1->>'password'::text, gen_salt('bf', 9)),
          ($1->>'first_name')::text,
          ($1->>'last_name')::text
        ) returning * into _user;

        -- related created user with community by invitation_code
        if nullif(($1->> 'invitation_code')::text, '') is not null then
          select * from public.invitations where code = ($1->>'invitation_code'::text) into _invitation;
          insert into public.community_users(user_id, community_id, role, created_at, updated_at) values (
            _user.id,
            _invitation.community_id,
            _invitation.role,
            now(),
            now()
          );
        end if;

        perform public.notify('welcome_user', json_build_object(
            'user_id', _user.id
        ));

      return ('common_user', _user.id)::postgraphql.jwt_token;
      end;
      $_$;


      ALTER FUNCTION postgraphql.register(data json) OWNER TO postgres;

      --
      -- Name: reset_password_change_password(text, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION reset_password_change_password(new_password text, token text) RETURNS jwt_token
      LANGUAGE plpgsql
      AS $$
      declare
      _jwt json;
      _user public.users;
      begin

        select postgraphql.reset_password_token_verify(token) into _jwt;

        select * from public.users where id = (_jwt->>'id')::int into _user;

        if nullif(new_password, '') is null then
          raise 'missing_password';
        end if;

        if length(new_password) < 6 then
          raise 'password_lt_six_chars';
        end if;

        update public.users
        set encrypted_password = public.crypt(new_password, public.gen_salt('bf', 9)), reset_password_token = null
        where id = _user.id;

        return (
          (case when _user.admin is true then 'admin' else 'common_user' end),
          _user.id
        )::postgraphql.jwt_token;
      end;
      $$;


      ALTER FUNCTION postgraphql.reset_password_change_password(new_password text, token text) OWNER TO postgres;

      --
      -- Name: reset_password_token_request(text, text, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION reset_password_token_request(email text, callback_url text, locale text DEFAULT 'pt-BR'::text) RETURNS void
      LANGUAGE plpgsql
      AS $_$
      declare
      _user public.users;
      _notification_template_id integer;
      _locale text;
      _notification public.notifications;
      begin
        _locale := coalesce(locale, 'pt-BR');

        -- find user by email
        select * from public.users u where u.email = $1
        into _user;

        if _user.id is null then
          raise 'user_not_found';
        end if;

        -- generate new reset token
        update public.users
        set reset_password_token = pgjwt.sign(json_build_object(
            'id', _user.id,
            'expirated_at', now() + interval '48 hours'
        ), public.configuration('jwt_secret'), 'HS512')
      where id = _user.id
      returning * into _user;

      -- TODO think other utilities this snippet
      -- get notification template id for user locale
      select nt.id from public.notification_templates nt where label = 'reset_password_instructions'
      and nt.locale = _locale limit 1
      into _notification_template_id;

      -- fallback on default locale when locale from user not found
      if _notification_template_id is null then
        select nt.id from public.notification_templates nt where label = 'reset_password_instructions'
        and nt.locale = 'pt-BR'
        into _notification_template_id;

        if _notification_template_id is null then
          raise 'invalid_notification_template';
        end if;
      end if;

      -- notify user about reset password instructions
      insert into public.notifications(user_id, notification_template_id, template_vars, created_at, updated_at)
      values (_user.id, _notification_template_id, json_build_object(
          'user', json_build_object(
            'id', _user.id,
            'uid', _user.uid,
            'email', _user.email,
            'first_name', _user.first_name,
            'last_name', _user.last_name,
            'reset_password_token', _user.reset_password_token,
            'callback_url', callback_url)
      ), now(), now()) returning * into _notification;

    -- notify to notification_channels
    perform pg_notify('notifications_channel',pgjwt.sign(json_build_object(
          'action', 'deliver_notification',
          'id', _notification.id,
          'created_at', now(),
          'sent_to_queuing', now(),
          'jit', now()::timestamp
    ), public.configuration('jwt_secret'), 'HS512'));
      end;
      $_$;


      ALTER FUNCTION postgraphql.reset_password_token_request(email text, callback_url text, locale text) OWNER TO postgres;

      --
      -- Name: reset_password_token_verify(text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION reset_password_token_verify(token text) RETURNS json
      LANGUAGE plpgsql STABLE
      AS $$
      declare
      _jwt json;
      _user public.users;
      begin

        if (select valid from pgjwt.verify(token, public.configuration('jwt_secret'), 'HS512')) is false then
          raise 'invalid_token';
        end if;

        select payload
        from pgjwt.verify(token, public.configuration('jwt_secret'), 'HS512')
        into _jwt;

        if to_date(_jwt->>'expirated_at', 'YYYY MM DD') <= now()::date then
          raise 'invalid_token';
        end if;

        select * from public.users u where u.id = (_jwt->>'id')::int and u.reset_password_token = token into _user;
        if _user is null then
          raise 'invalid_token';
        end if;

        return _jwt;
      end;
      $$;


      ALTER FUNCTION postgraphql.reset_password_token_verify(token text) OWNER TO postgres;

      SET search_path = public, pg_catalog;

      --
      -- Name: activists; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE activists (
        id integer NOT NULL,
        name character varying NOT NULL,
        email character varying NOT NULL,
        phone character varying,
        document_number character varying,
        document_type character varying,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        city character varying,
        first_name text,
        last_name text
      );


      ALTER TABLE activists OWNER TO postgres;

      --
      -- Name: community_activists; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE community_activists (
        id integer NOT NULL,
        community_id integer NOT NULL,
        activist_id integer NOT NULL,
        search_index tsvector,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL,
        profile_data jsonb
      );


      ALTER TABLE community_activists OWNER TO postgres;

      --
      -- Name: community_users; Type: TABLE; Schema: public; Owner: postgres
      --

      CREATE TABLE community_users (
        id integer NOT NULL,
        user_id integer,
        community_id integer,
        role integer,
        created_at timestamp without time zone NOT NULL,
        updated_at timestamp without time zone NOT NULL
      );


      ALTER TABLE community_users OWNER TO postgres;

      SET search_path = postgraphql, pg_catalog;

      --
      -- Name: activists; Type: VIEW; Schema: postgraphql; Owner: postgres
      --

      CREATE VIEW activists AS
      WITH current_communities_access AS (
        SELECT DISTINCT cu.community_id
        FROM public.community_users cu
        WHERE ((cu.user_id = current_user_id()) OR (pg_catalog."current_user"() = 'admin'::name))
      )
      SELECT ca.community_id,
      ca.activist_id AS id,
      ((ca.profile_data ->> 'name'::text))::character varying AS name,
      a.email,
      ((ca.profile_data ->> 'phone'::text))::character varying AS phone,
      ((ca.profile_data ->> 'document_number'::text))::character varying AS document_number,
      ca.created_at,
      (ca.profile_data)::json AS data,
      '{}'::json AS mobilizations,
      '{}'::jsonb AS tags
      FROM (public.community_activists ca
        JOIN public.activists a ON ((a.id = ca.activist_id)))
      WHERE (ca.community_id IN ( SELECT current_communities_access.community_id
          FROM current_communities_access));


      ALTER TABLE activists OWNER TO postgres;

      --
      -- Name: search_activists_on_community(text, integer, integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
      --

      CREATE FUNCTION search_activists_on_community(query text, ctx_community_id integer, days_ago integer) RETURNS SETOF activists
      LANGUAGE sql STABLE
      AS $$
      with search_index as (
        select
        atg.community_id,
        atg.activist_id,
        json_agg(json_build_object(
            'tag_name', tag.name,
            'activist_name', a.name,
            'activist_email', a.email
        )) package_search_vector
      from public.activist_tags atg
      join public.taggings tgs on tgs.taggable_type = 'ActivistTag'
      and tgs.taggable_id = atg.id
      join public.tags tag on tag.id = tgs.tag_id
      join public.activists a on a.id = atg.activist_id
      where atg.community_id = ctx_community_id
      and (
        case when days_ago is null or days_ago = 0 then true
        else atg.created_at >= (current_timestamp - (days_ago||' days')::interval) end
        )                      
        group by atg.activist_id, atg.community_id, a.id
      ) select
      act.*
      from search_index si
      join lateral (
        select exists (
          select
          true
          from json_array_elements(si.package_search_vector)  as vec
          where (setweight(
              to_tsvector('portuguese', replace((regexp_split_to_array((vec->>'tag_name')::text, '_'::text))[2], '-', ' ')), 'A'
              )||setweight(
              to_tsvector('portuguese', (vec->>'tag_name')::text), 'B'
              )||setweight(
              to_tsvector('portuguese', vec->>'activist_name'), 'B'
              )||setweight(
              to_tsvector('portuguese', vec->>'activist_email'), 'C'
          ))::tsvector @@ plainto_tsquery('portuguese', query)
      ) as found
    ) as si_r on found
    join lateral (
      SELECT pa.*
      FROM postgraphql.activists pa
      WHERE pa.community_id = si.community_id
      and pa.id = si.activist_id
    ) as act on true
    $$;


    ALTER FUNCTION postgraphql.search_activists_on_community(query text, ctx_community_id integer, days_ago integer) OWNER TO postgres;

    --
    -- Name: total_avg_donations_by_community(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_avg_donations_by_community(com_id integer) RETURNS double precision
    LANGUAGE sql
    AS $$
    select avg(d.payable_amount)
    from postgraphql.donations d where d.community_id = com_id
    and d.transaction_status = 'paid'
    $$;


    ALTER FUNCTION postgraphql.total_avg_donations_by_community(com_id integer) OWNER TO postgres;

    --
    -- Name: total_avg_donations_by_community_interval(integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_avg_donations_by_community_interval(com_id integer, timeinterval interval) RETURNS double precision
    LANGUAGE sql
    AS $$
    select avg(d.payable_amount)
    from postgraphql.donations d where d.community_id = com_id
    and d.transaction_status = 'paid'
    and d.payment_date > CURRENT_TIMESTAMP - timeinterval
    $$;


    ALTER FUNCTION postgraphql.total_avg_donations_by_community_interval(com_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_avg_donations_by_mobilization(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_avg_donations_by_mobilization(mob_id integer) RETURNS double precision
    LANGUAGE sql
    AS $$
    select avg(d.payable_amount)
    from postgraphql.donations d where d.mobilization_id = mob_id
    and d.transaction_status = 'paid'
    $$;


    ALTER FUNCTION postgraphql.total_avg_donations_by_mobilization(mob_id integer) OWNER TO postgres;

    --
    -- Name: total_avg_donations_by_mobilization_interval(integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_avg_donations_by_mobilization_interval(mob_id integer, timeinterval interval) RETURNS double precision
    LANGUAGE sql
    AS $$
    select avg(d.payable_amount)
    from postgraphql.donations d where d.mobilization_id = mob_id
    and d.transaction_status = 'paid'
    and d.payment_date > CURRENT_TIMESTAMP - timeinterval
    $$;


    ALTER FUNCTION postgraphql.total_avg_donations_by_mobilization_interval(mob_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_donations_from_community(com_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_donations_from_mobilization(mob_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_donations_from_mobilization_interval(mod_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mod_id
        and d.transaction_status = status
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_donations_from_mobilization_interval(mod_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_subscription_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_subscription_donations_from_community(com_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.subscription_id is not null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_subscription_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_subscription_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_subscription_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.subscription_id is not null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_subscription_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_subscription_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_subscription_donations_from_mobilization(mob_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.subscription_id is not null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_subscription_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_subscription_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_subscription_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status
        and d.subscription_id is not null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_subscription_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_uniq_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_uniq_donations_from_community(com_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.subscription_id is null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_uniq_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_uniq_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_uniq_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.subscription_id is null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_uniq_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_count_uniq_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_uniq_donations_from_mobilization(mob_id integer, status text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.subscription_id is null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_uniq_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_count_uniq_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_count_uniq_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select count(1) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status
        and d.subscription_id is null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_count_uniq_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_donations_from_community(com_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_donations_from_mobilization(mob_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_subscription_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_subscription_donations_from_community(com_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.subscription_id is not null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_subscription_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_subscription_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_subscription_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.subscription_id is not null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_subscription_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_subscription_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_subscription_donations_from_mobilization(mob_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.subscription_id is not null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_subscription_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_subscription_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_subscription_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status
        and d.subscription_id is not null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_subscription_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_transfer_operations_from_community(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_transfer_operations_from_community(community_id integer) RETURNS numeric
    LANGUAGE sql
    AS $_$
    WITH current_communities_access AS (
      SELECT DISTINCT(cu.community_id)
      FROM community_users cu
      WHERE ((cu.user_id = postgraphql.current_user_id()) OR ("current_user"() = 'admin'::name))
    ) select sum(bos.operation_amount) 
    from public.balance_operation_summaries bos
    where bos.operation_type = 'transfer' 
    and bos.community_id = $1 and (bos.community_id IN (
        SELECT current_communities_access.community_id FROM current_communities_access));
    $_$;


    ALTER FUNCTION postgraphql.total_sum_transfer_operations_from_community(community_id integer) OWNER TO postgres;

    --
    -- Name: FUNCTION total_sum_transfer_operations_from_community(community_id integer); Type: COMMENT; Schema: postgraphql; Owner: postgres
    --

    COMMENT ON FUNCTION total_sum_transfer_operations_from_community(community_id integer) IS 'Get total sum of all transfers to community';


    --
    -- Name: total_sum_uniq_donations_from_community(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_uniq_donations_from_community(com_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.subscription_id is null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_uniq_donations_from_community(com_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_uniq_donations_from_community_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_uniq_donations_from_community_interval(com_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.community_id = com_id
        and d.transaction_status = status
        and d.subscription_id is null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_uniq_donations_from_community_interval(com_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_sum_uniq_donations_from_mobilization(integer, text); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_uniq_donations_from_mobilization(mob_id integer, status text) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.subscription_id is null
        and d.transaction_status = status), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_uniq_donations_from_mobilization(mob_id integer, status text) OWNER TO postgres;

    --
    -- Name: total_sum_uniq_donations_from_mobilization_interval(integer, text, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_sum_uniq_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) RETURNS double precision
    LANGUAGE sql IMMUTABLE
    AS $$
    select coalesce((select sum(d.payable_amount) 
        from postgraphql.donations d
        where d.mobilization_id = mob_id
        and d.transaction_status = status
        and d.subscription_id is null
        and d.payment_date > CURRENT_TIMESTAMP - timeinterval), 0);
    $$;


    ALTER FUNCTION postgraphql.total_sum_uniq_donations_from_mobilization_interval(mob_id integer, status text, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_uniq_activists_by_kind_and_community(text, integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_uniq_activists_by_kind_and_community(kind_name text, com_id integer) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where community_id = com_id
    and participate_kind = kind_name
    $$;


    ALTER FUNCTION postgraphql.total_uniq_activists_by_kind_and_community(kind_name text, com_id integer) OWNER TO postgres;

    --
    -- Name: total_uniq_activists_by_kind_and_community_interval(text, integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_uniq_activists_by_kind_and_community_interval(kind_name text, com_id integer, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where community_id = com_id
    and participate_kind = kind_name
    and participate_at > CURRENT_TIMESTAMP - timeinterval;
    $$;


    ALTER FUNCTION postgraphql.total_uniq_activists_by_kind_and_community_interval(kind_name text, com_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_uniq_activists_by_kind_and_mobilization(text, integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_uniq_activists_by_kind_and_mobilization(kind_name text, mob_id integer) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where mobilization_id = mob_id
    and participate_kind = kind_name
    $$;


    ALTER FUNCTION postgraphql.total_uniq_activists_by_kind_and_mobilization(kind_name text, mob_id integer) OWNER TO postgres;

    --
    -- Name: total_uniq_activists_by_kind_and_mobilization_interval(text, integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_uniq_activists_by_kind_and_mobilization_interval(kind_name text, mob_id integer, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where mobilization_id = mob_id
    and participate_kind = kind_name
    and participate_at > CURRENT_TIMESTAMP - timeinterval;
    $$;


    ALTER FUNCTION postgraphql.total_uniq_activists_by_kind_and_mobilization_interval(kind_name text, mob_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_unique_activists_by_community(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_unique_activists_by_community(com_id integer) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where community_id = com_id;
    $$;


    ALTER FUNCTION postgraphql.total_unique_activists_by_community(com_id integer) OWNER TO postgres;

    --
    -- Name: total_unique_activists_by_community_interval(integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_unique_activists_by_community_interval(com_id integer, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where community_id = com_id
    and participate_at > CURRENT_TIMESTAMP - timeinterval;
    $$;


    ALTER FUNCTION postgraphql.total_unique_activists_by_community_interval(com_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: total_unique_activists_by_mobilization(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_unique_activists_by_mobilization(mob_id integer) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where mobilization_id = mob_id;
    $$;


    ALTER FUNCTION postgraphql.total_unique_activists_by_mobilization(mob_id integer) OWNER TO postgres;

    --
    -- Name: total_unique_activists_by_mobilization_interval(integer, interval); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION total_unique_activists_by_mobilization_interval(mob_id integer, timeinterval interval) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $$
    select
    count(distinct activist_id) as total
    from postgraphql.participations
    where mobilization_id = mob_id
    and participate_at > CURRENT_TIMESTAMP - timeinterval;
    $$;


    ALTER FUNCTION postgraphql.total_unique_activists_by_mobilization_interval(mob_id integer, timeinterval interval) OWNER TO postgres;

    --
    -- Name: trending_mobilizations(integer); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION trending_mobilizations(days integer) RETURNS SETOF mobilizations
    LANGUAGE sql STABLE
    AS $$
    select m.*
    from postgraphql.mobilizations m
    left join lateral (
      select count(1)
      from public.activist_actions aa
      where aa.mobilization_id  = m.id
      and aa.action_created_date >= now()::date - (days || ' days')::interval
    ) as score on true
    order by score desc;
    $$;


    ALTER FUNCTION postgraphql.trending_mobilizations(days integer) OWNER TO postgres;

    --
    -- Name: update_bot(json); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION update_bot(bot_data json) RETURNS json
    LANGUAGE plpgsql
    AS $$
    declare
    bot_json public.facebook_bot_configurations;
    begin
      update public.facebook_bot_configurations
      set community_id = coalesce((bot_data ->> 'community_id')::integer, community_id)::integer, 
      messenger_app_secret = coalesce((bot_data ->> 'messenger_app_secret'), messenger_app_secret), 
      messenger_validation_token = coalesce((bot_data ->> 'messenger_validation_token'), messenger_validation_token),
      messenger_page_access_token = coalesce((bot_data ->> 'messenger_page_access_token'), messenger_validation_token), 
      data = coalesce((bot_data ->> 'data')::jsonb, data), 
      updated_at = now()
      where id = (bot_data ->> 'id')::integer
      returning * into bot_json;

      return row_to_json(bot_json);
    end;
    $$;


    ALTER FUNCTION postgraphql.update_bot(bot_data json) OWNER TO postgres;

    SET search_path = public, pg_catalog;

    --
    -- Name: facebook_bot_campaign_activists; Type: TABLE; Schema: public; Owner: postgres
    --

    CREATE TABLE facebook_bot_campaign_activists (
      id integer NOT NULL,
      facebook_bot_campaign_id integer NOT NULL,
      facebook_bot_activist_id integer NOT NULL,
      received boolean DEFAULT false NOT NULL,
      log jsonb DEFAULT '{}'::jsonb,
      created_at timestamp without time zone NOT NULL,
      updated_at timestamp without time zone NOT NULL
    );


    ALTER TABLE facebook_bot_campaign_activists OWNER TO postgres;

    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: update_facebook_bot_campaign_activists(integer, boolean, jsonb); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION update_facebook_bot_campaign_activists(facebook_bot_campaign_activist_id integer, ctx_received boolean, ctx_log jsonb) RETURNS public.facebook_bot_campaign_activists
    LANGUAGE plpgsql
    AS $$
    DECLARE
    v_facebook_bot_campaign_activist public.facebook_bot_campaign_activists;
    BEGIN
      UPDATE public.facebook_bot_campaign_activists SET
      received = ctx_received,
      "log" = ctx_log,
      updated_at = NOW()
      WHERE id = facebook_bot_campaign_activist_id
      RETURNING * INTO v_facebook_bot_campaign_activist;
      RETURN v_facebook_bot_campaign_activist;
    END;
    $$;


    ALTER FUNCTION postgraphql.update_facebook_bot_campaign_activists(facebook_bot_campaign_activist_id integer, ctx_received boolean, ctx_log jsonb) OWNER TO postgres;

    --
    -- Name: update_twilio_configuration(twilio_configurations); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION update_twilio_configuration(config twilio_configurations) RETURNS twilio_configurations
    LANGUAGE plpgsql
    AS $$
    DECLARE twilio_configuration postgraphql.twilio_configurations;
    BEGIN
      UPDATE postgraphql.twilio_configurations
      SET
      twilio_account_sid = COALESCE(
        CONFIG.twilio_account_sid,
        twilio_configuration.twilio_account_sid
      ),
      twilio_auth_token = COALESCE(
        CONFIG.twilio_auth_token,
        twilio_configuration.twilio_auth_token
      ),
      twilio_number = COALESCE(
        CONFIG.twilio_number,
        twilio_configuration.twilio_number
      ),
      updated_at = now()
      WHERE community_id = CONFIG.community_id
      RETURNING * INTO twilio_configuration;
      RETURN twilio_configuration;
    END;
    $$;


    ALTER FUNCTION postgraphql.update_twilio_configuration(config twilio_configurations) OWNER TO postgres;

    --
    -- Name: user_mobilizations; Type: VIEW; Schema: postgraphql; Owner: postgres
    --

    CREATE VIEW user_mobilizations AS
    SELECT m.id,
    m.name,
    m.created_at,
    m.updated_at,
    m.user_id,
    m.color_scheme,
    m.google_analytics_code,
    m.goal,
    m.header_font,
    m.body_font,
    m.facebook_share_title,
    m.facebook_share_description,
    m.facebook_share_image,
    m.slug,
    m.custom_domain,
    m.twitter_share_text,
    m.community_id,
    m.favicon,
    m.deleted_at,
    m.status
    FROM (mobilizations m
      JOIN public.community_users cou ON ((cou.community_id = m.community_id)))
    WHERE (cou.user_id = current_user_id());


    ALTER TABLE user_mobilizations OWNER TO postgres;

    --
    -- Name: user_mobilizations_community(user_mobilizations); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION user_mobilizations_community(m user_mobilizations) RETURNS communities
    LANGUAGE sql STABLE
    AS $$
    select c.*
    from postgraphql.communities c
    where c.id = m.community_id
    $$;


    ALTER FUNCTION postgraphql.user_mobilizations_community(m user_mobilizations) OWNER TO postgres;

    --
    -- Name: user_mobilizations_score(user_mobilizations); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION user_mobilizations_score(m user_mobilizations) RETURNS integer
    LANGUAGE sql STABLE
    AS $$
    select count(1)::INT
    from public.activist_actions aa
    where aa.mobilization_id  = m.id
    $$;


    ALTER FUNCTION postgraphql.user_mobilizations_score(m user_mobilizations) OWNER TO postgres;

    --
    -- Name: watch_twilio_call_transitions(twilio_calls_arguments); Type: FUNCTION; Schema: postgraphql; Owner: postgres
    --

    CREATE FUNCTION watch_twilio_call_transitions(call twilio_calls_arguments) RETURNS watch_twilio_call_transition_record_set
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT tc.widget_id AS widget_id,
    tc.activist_id AS activist_id,
    tc.id AS twilio_call_id,
    tc.twilio_account_sid AS twilio_call_account_sid,
    tc.twilio_call_sid AS twilio_call_call_sid,
    tc."from" AS twilio_call_from,
    tc."to" AS twilio_call_to,
    tct.id AS twilio_call_transition_id,
    tct.sequence_number AS twilio_call_transition_sequence_number,
    tct.status AS twilio_call_transition_status,
    tct.call_duration AS twilio_call_transition_call_duration,
    tct.created_at AS twilio_call_transition_created_at,
    tct.updated_at AS twilio_call_transition_updated_at
    FROM public.twilio_calls AS tc
    RIGHT JOIN public.twilio_call_transitions AS tct ON tc.twilio_call_sid = tct.twilio_call_sid
    WHERE tc.widget_id = CALL.widget_id
    AND tc."from" = CALL."from"
    ORDER BY tc.id DESC,
    tct.sequence_number DESC LIMIT 1;
    $$;


    ALTER FUNCTION postgraphql.watch_twilio_call_transitions(call twilio_calls_arguments) OWNER TO postgres;

    SET search_path = public, pg_catalog;

    --
    -- Name: configuration(text); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION configuration(name text) RETURNS text
    LANGUAGE sql
    AS $_$
    select value from public.configurations where name = $1;
    $_$;


    ALTER FUNCTION public.configuration(name text) OWNER TO postgres;

    --
    -- Name: facebook_activist_message_full_text_index(text); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION facebook_activist_message_full_text_index(v_message text) RETURNS tsvector
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RETURN setweight(to_tsvector('portuguese', v_message), 'A');
    END;
    $$;


    ALTER FUNCTION public.facebook_activist_message_full_text_index(v_message text) OWNER TO postgres;

    --
    -- Name: form_entries; Type: TABLE; Schema: public; Owner: postgres
    --

    CREATE TABLE form_entries (
      id integer NOT NULL,
      widget_id integer,
      fields text,
      created_at timestamp without time zone NOT NULL,
      updated_at timestamp without time zone NOT NULL,
      synchronized boolean,
      activist_id integer,
      mailchimp_syncronization_at timestamp without time zone,
      mailchimp_syncronization_error_reason text,
      cached_community_id integer
    );


    ALTER TABLE form_entries OWNER TO postgres;

    --
    -- Name: first_time_in_entries(form_entries); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION first_time_in_entries(entry form_entries) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    select (select
      count(1)
      from form_entries fe2
      where 
      entry.activist_id = fe2.activist_id 
      and fe2.created_at <= entry.created_at
      and entry.id <> fe2.id
      limit 2) > 1;
    $$;


    ALTER FUNCTION public.first_time_in_entries(entry form_entries) OWNER TO postgres;

    --
    -- Name: activist_pressures; Type: TABLE; Schema: public; Owner: postgres
    --

    CREATE TABLE activist_pressures (
      id integer NOT NULL,
      activist_id integer,
      widget_id integer,
      created_at timestamp without time zone NOT NULL,
      updated_at timestamp without time zone NOT NULL,
      synchronized boolean,
      mailchimp_syncronization_at timestamp without time zone,
      mailchimp_syncronization_error_reason text,
      cached_community_id integer
    );


    ALTER TABLE activist_pressures OWNER TO postgres;

    --
    -- Name: first_time_in_pressures(activist_pressures); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION first_time_in_pressures(pressure activist_pressures) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    select (select
      count(1)
      from activist_pressures ap2
      where 
      pressure.activist_id = ap2.activist_id 
      and ap2.created_at <= pressure.created_at
      and ap2.id <> pressure.id
      limit 2) > 1;
    $$;


    ALTER FUNCTION public.first_time_in_pressures(pressure activist_pressures) OWNER TO postgres;

    --
    -- Name: generate_activists_from_generic_resource_with_widget(); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION generate_activists_from_generic_resource_with_widget() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    declare
    v_mobilization public.mobilizations;
    v_profile_data json;
    begin
      IF TG_TABLE_NAME in ('subscriptions', 'form_entries', 'donations', 'activist_pressures')
        AND NEW.activist_id is not null AND NEW.widget_id is not null THEN

        select distinct(m.*) from mobilizations m
        join blocks b on b.mobilization_id = m.id
        join widgets w on w.block_id = b.id
        where w.id = NEW.widget_id
        into v_mobilization;

        select row_to_json(activists.*) from activists where id = NEW.activist_id
        into v_profile_data;

        IF v_mobilization.id IS NOT NULL THEN
          if not exists(select true
            from community_activists
            where community_id = v_mobilization.community_id and activist_id = NEW.activist_id) then
            insert into community_activists (community_id, activist_id, created_at, updated_at, profile_data)
            values (v_mobilization.community_id, NEW.activist_id, now(), now(), v_profile_data::jsonb);
          end if;

          if not exists(select true
            from mobilization_activists
            where mobilization_id = v_mobilization.id and activist_id = NEW.activist_id) then
            insert into mobilization_activists (mobilization_id, activist_id, created_at, updated_at)
            values (v_mobilization.id, NEW.activist_id, now(), now());
          end if;
        END IF;

      END IF;
      return NEW;
    end;
    $$;


    ALTER FUNCTION public.generate_activists_from_generic_resource_with_widget() OWNER TO postgres;

    --
    -- Name: FUNCTION generate_activists_from_generic_resource_with_widget(); Type: COMMENT; Schema: public; Owner: postgres
    --

    COMMENT ON FUNCTION generate_activists_from_generic_resource_with_widget() IS 'insert a row on mobilization_activists and community_activists linking from NEW.activist_id / widget_id';


    --
    -- Name: generate_notification_tags(json); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION generate_notification_tags(relations json) RETURNS json
    LANGUAGE plpgsql
    AS $_$
    declare
    _subscription public.subscriptions;
    _donation public.donations;
    _last_subscription_payment public.donations;
    _activist public.activists;
    _community public.communities;
    _mobilization public.mobilizations;
    _user public.users;
    _result json;
    begin
      -- get subscription when json->>'subscription_id' is present
      select * from public.subscriptions where id = ($1->>'subscription_id')::integer
      into _subscription;

      -- get donation when json->>'donation_id' is present
      select * from public.donations where id = ($1->>'donation_id')::integer
      into _donation;

      -- get last subscription donation when json ->> 'subscription_id' is present
      select * from public.donations where local_subscription_id = _subscription.id
      order by created_at desc limit 1 into _last_subscription_payment;

      -- get activist when json ->> 'activist_id' is present or subscription/donation is found
      select * from public.activists where id = coalesce(coalesce(($1->>'activist_id')::integer, _subscription.activist_id), _donation.activist_id)
      into _activist;

      -- get community when json->>'community_id' is present or subscription/donation is found
      select * from public.communities where id = coalesce(coalesce(($1->>'community_id')::integer, _subscription.community_id), _donation.cached_community_id)
      into _community;

      -- get user when json->>'user_id' is present
      select * from public.users where id = ($1->>'user_id')::integer 
      into _user;

      -- get mobilization from subscription/donation widget when block is defined
      select * from mobilizations m
      join blocks b on b.mobilization_id = m.id
      join widgets w on w.block_id = b.id
      where w.id = coalesce(_subscription.widget_id, _donation.widget_id)
      into _mobilization;


      -- build and return template tags json after collect all data
      _result := json_build_object(
        'subscription_id', _subscription.id,
        'payment_method', coalesce(_subscription.payment_method, _donation.payment_method),
        'donation_id', _donation.id,
        'widget_id', _donation.widget_id,
        'mobilization_id', _mobilization.id,
        'mobilization_name', _mobilization.name,
        'boleto_expiration_date', (_donation.gateway_data ->> 'boleto_expiration_date'),
        'boleto_barcode', (_donation.gateway_data ->> 'boleto_barcode'),
        'boleto_url', (_donation.gateway_data ->> 'boleto_url'),
        'manage_url', (
          case when _subscription.id is not null then
            'https://app.bonde.org/subscriptions/'||_subscription.id||'/edit?token='||_subscription.token
          else null end
          ),
          'amount', (coalesce(_subscription.amount, _donation.amount) / 100),
          'user', json_build_object(
            'first_name', _user.first_name,
            'last_name', _user.last_name
          ),
          'customer', json_build_object(
            'name', _activist.name,
            'first_name', _activist.first_name,
            'last_name', _activist.last_name
          ),
          'community', json_build_object(
            'id', _community.id,
            'name', _community.name,
            'image', _community.image
          ),
          'last_donation', json_build_object(
            'payment_method', _last_subscription_payment.payment_method,
            'widget_id', _last_subscription_payment.widget_id,
            'mobilization_id', _mobilization.id,
            'mobilization_name', _mobilization.name,
            'boleto_expiration_date', (_last_subscription_payment.gateway_data ->> 'boleto_expiration_date'),
            'boleto_barcode', (_last_subscription_payment.gateway_data ->> 'boleto_barcode'),
            'boleto_url', (_last_subscription_payment.gateway_data ->> 'boleto_url')
          )
        );

        return _result;
    end;
    $_$;


    ALTER FUNCTION public.generate_notification_tags(relations json) OWNER TO postgres;

    --
    -- Name: subscriptions; Type: TABLE; Schema: public; Owner: postgres
    --

    CREATE TABLE subscriptions (
      id integer NOT NULL,
      widget_id integer,
      activist_id integer,
      community_id integer,
      card_data jsonb,
      status character varying,
      period integer DEFAULT 30,
      amount integer,
      created_at timestamp without time zone NOT NULL,
      updated_at timestamp without time zone NOT NULL,
      payment_method text NOT NULL,
      token uuid DEFAULT uuid_generate_v4(),
      gateway_subscription_id integer,
      synchronized boolean,
      mailchimp_syncronization_at timestamp without time zone,
      mailchimp_syncronization_error_reason text,
      gateway_customer_id integer,
      customer_data jsonb,
      schedule_next_charge_at timestamp without time zone
    );


    ALTER TABLE subscriptions OWNER TO postgres;

    --
    -- Name: next_transaction_charge_date(subscriptions); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION next_transaction_charge_date(subscriptions) RETURNS timestamp without time zone
    LANGUAGE sql STABLE
    AS $_$
    select
    d.created_at + '1 month'::interval
    from public.donations d 
    where d.transaction_status = 'paid'
    and d.local_subscription_id = $1.id
    order by d.created_at desc limit 1;
    $_$;


    ALTER FUNCTION public.next_transaction_charge_date(subscriptions) OWNER TO postgres;

    --
    -- Name: nossas_recipient_id(); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION nossas_recipient_id() RETURNS text
    LANGUAGE sql
    AS $$
    select 're_cinemdtb204bk2l5x8zri0iv8'::text;
    $$;


    ALTER FUNCTION public.nossas_recipient_id() OWNER TO postgres;

    --
    -- Name: notify(text, json); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION notify(template_name text, relations json) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER
    AS $_$
    declare
    _community public.communities;
    _user public.users;
    _activist public.activists;
    _notification public.notifications;
    _notification_template public.notification_templates;
    _template_vars json;
    begin
      -- get community from relations
      select * from public.communities where id = ($2->>'community_id')::integer
      into _community;

      -- get user from relations
      select * from public.users where id = ($2->>'user_id')::integer
      into _user;

      -- get activist when set on relations
      select * from public.activists where id = ($2->>'activist_id')::integer
      into _activist;

      -- try get notification template from community
      select * from public.notification_templates nt
      where nt.community_id = ($2->>'community_id')::integer
      and nt.label = $1
      into _notification_template;

      -- if not found on community try get without community
      if _notification_template is null then
        select * from public.notification_templates nt
        where nt.label = $1
        into _notification_template;

        if _notification_template is null then
          raise 'invalid_notification_template';
        end if;
      end if;

      _template_vars := public.generate_notification_tags(relations);

      -- insert notification to database
      insert into notifications(activist_id, notification_template_id, template_vars, created_at, updated_at, user_id, email)
      values (_activist.id, _notification_template.id, _template_vars::jsonb, now(), now(), _user.id, $2->>'email')
      returning * into _notification;

      -- notify to notification_channels
      perform pg_notify('notifications_channel',pgjwt.sign(json_build_object(
            'action', 'deliver_notification',
            'id', _notification.id,
            'created_at', now(),
            'sent_to_queuing', now(),
            'jit', now()::timestamp
      ), public.configuration('jwt_secret'), 'HS512'));

  return json_build_object('id', _notification.id);
    end;
    $_$;


    ALTER FUNCTION public.notify(template_name text, relations json) OWNER TO postgres;

    --
    -- Name: notify_create_twilio_configuration_trigger(); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION notify_create_twilio_configuration_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      IF (TG_OP = 'INSERT') THEN
        perform pg_notify('twilio_configuration_created', row_to_json(NEW)::text);
      END IF;

      IF (TG_OP = 'UPDATE') THEN
        perform pg_notify('twilio_configuration_updated', row_to_json(NEW)::text);
      END IF;

      RETURN NEW;
    END;
    $$;


    ALTER FUNCTION public.notify_create_twilio_configuration_trigger() OWNER TO postgres;

    --
    -- Name: notify_twilio_call_trigger(); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION notify_twilio_call_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
    BEGIN perform pg_notify('twilio_call_created', row_to_json(NEW)::text);
      RETURN NEW;
    END;
    $$;


    ALTER FUNCTION public.notify_twilio_call_trigger() OWNER TO postgres;

    --
    -- Name: donations; Type: TABLE; Schema: public; Owner: postgres
    --

    CREATE TABLE donations (
      id integer NOT NULL,
      widget_id integer,
      created_at timestamp without time zone NOT NULL,
      updated_at timestamp without time zone NOT NULL,
      token character varying,
      payment_method character varying,
      amount integer,
      email character varying,
      card_hash character varying,
      customer hstore,
      skip boolean DEFAULT false,
      transaction_id character varying,
      transaction_status character varying DEFAULT 'pending'::character varying,
      subscription boolean,
      credit_card character varying,
      activist_id integer,
      subscription_id character varying,
      period integer,
      plan_id integer,
      parent_id integer,
      payables jsonb,
      gateway_data jsonb,
      payable_transfer_id integer,
      old_synch boolean,
      converted_from integer,
      synchronized boolean,
      local_subscription_id integer,
      mailchimp_syncronization_at timestamp without time zone,
      mailchimp_syncronization_error_reason text,
      checkout_data jsonb,
      cached_community_id integer
    );


    ALTER TABLE donations OWNER TO postgres;

    --
    -- Name: payable_fee(donations); Type: FUNCTION; Schema: public; Owner: postgres
    --

    CREATE FUNCTION payable_fee(d donations) RETURNS numeric
    LANGUAGE sql IMMUTABLE
    AS $$
    select (
      case
      when d.payables is not null and jsonb_array_length(d.payables) < 2 then
        (
          case 
          when extract(year from d.created_at) <= 2016 then        
            (((d.payables -> 0 ->> 'amount')::integer / 100.0) * 0.15)  - ((d.payables -> 0 ->> 'fee')::integer / 100.0)
          else
            (((d.payables -> 0 ->> 'amount')::integer / 100.0) * 0.13) - ((d.payables -> 0 ->> 'fee')::integer / 100.0)
          end
        )
      when d.payables is null then
        (
          case 
          when extract(year from d.created_at) <= 2016 then
            (d.amount / 100.0) * 0.15
          else
            (d.amount / 100.0) * 0.13
          end        
        )    
      else
        (
          select 
          ((p ->> 'amount')::integer / 100.0) - ((p ->> 'fee')::integer / 100.0)
          from jsonb_array_elements(d.payables) p
          where (p ->> 'fee')::integer <> 0
          limit 1
        )
      end)::decimal - (case d.payment_method 
      when 'boleto' then 0
      else coalesce(((d.gateway_data ->> 'cost')::integer / 100.0), 0) end)
        $$;


        ALTER FUNCTION public.payable_fee(d donations) OWNER TO postgres;

        --
        -- Name: receiving_unpaid_notifications(subscriptions); Type: FUNCTION; Schema: public; Owner: postgres
        --

        CREATE FUNCTION receiving_unpaid_notifications(subscriptions) RETURNS boolean
        LANGUAGE plpgsql STABLE
        AS $_$
        declare
        _last_paid_donation public.donations;
        begin
          select * from donations
          where local_subscription_id = $1.id
          and transaction_status = 'paid'
          order by created_at desc
          limit 1
          into _last_paid_donation;

          if _last_paid_donation.id is not null then
            return coalesce((
                select count(1) <= 2 
                from notifications n
                join notification_templates nt on nt.id = n.notification_template_id
                where nt.label = 'unpaid_subscription'
                and (n.template_vars->>'subscription_id')::integer = $1.id
                and n.created_at >= _last_paid_donation.created_at
            ), true);
        else
          return (
            select count(1) <= 2 
            from notifications n
            join notification_templates nt on nt.id = n.notification_template_id
            where nt.label = 'unpaid_subscription'
            and (n.template_vars->>'subscription_id')::integer = $1.id
          );
          end if;
        end;
        $_$;


        ALTER FUNCTION public.receiving_unpaid_notifications(subscriptions) OWNER TO postgres;

        --
        -- Name: refresh_custom_domain_frontend(); Type: FUNCTION; Schema: public; Owner: postgres
        --

        CREATE FUNCTION refresh_custom_domain_frontend() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        begin
          if new.traefik_host_rule is not null then
            perform pg_notify('dns_channel', pgjwt.sign(json_build_object(
                  'action', 'refresh_frontend',
                  'id', new.id,
                  'created_at', now(),
                  'sent_to_queuing', now(),
                  'jit', now()::timestamp
            ), public.configuration('jwt_secret'), 'HS512'));
          end if;

          return new;
        end;
        $$;


        ALTER FUNCTION public.refresh_custom_domain_frontend() OWNER TO postgres;

        --
        -- Name: slugfy(text); Type: FUNCTION; Schema: public; Owner: postgres
        --

        CREATE FUNCTION slugfy(text) RETURNS text
        LANGUAGE sql IMMUTABLE
        AS $_$
        select regexp_replace(replace(unaccent(lower($1)), ' ', '-'), '[^a-z0-9-_]+', '', 'g');
        $_$;


        ALTER FUNCTION public.slugfy(text) OWNER TO postgres;

        --
        -- Name: update_facebook_bot_activists_full_text_index(); Type: FUNCTION; Schema: public; Owner: postgres
        --

        CREATE FUNCTION update_facebook_bot_activists_full_text_index() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
        v_facebook_bot_activists public.facebook_bot_activists;
        v_payload jsonb;
        v_quick_reply text;
        v_messages tsvector;
        v_quick_replies text[];
        BEGIN
          SELECT *
          FROM public.facebook_bot_activists
          WHERE fb_context_recipient_id = NEW.fb_context_recipient_id
          INTO v_facebook_bot_activists;

          IF NEW.interaction ->> 'is_bot' IS NULL THEN
            v_payload := NEW.interaction -> 'payload';
            v_quick_reply := v_payload -> 'message' -> 'quick_reply' ->> 'payload';
            v_messages := CASE WHEN v_quick_reply IS NULL THEN
            public.facebook_activist_message_full_text_index(
              v_payload -> 'message' ->> 'text'
            )
          END;

          IF v_quick_reply IS NOT NULL THEN
            v_quick_replies := ARRAY[v_quick_reply]::text[];
          END IF;

          IF v_facebook_bot_activists IS NULL THEN
            INSERT INTO public.facebook_bot_activists (
              fb_context_recipient_id,
              fb_context_sender_id,
              data,
              messages,
              quick_replies,
              interaction_dates,
              created_at,
              updated_at
              ) VALUES (
              NEW.fb_context_recipient_id,
              NEW.fb_context_sender_id,
              NEW.interaction -> 'profile',
              v_messages,
              COALESCE(v_quick_replies, ARRAY[]::text[]),
              ARRAY[NEW.created_at]::timestamp without time zone[],
              NEW.created_at,
              NEW.updated_at
            );
          ELSE
            UPDATE public.facebook_bot_activists
            SET
            interaction_dates = ARRAY_APPEND(interaction_dates, NEW.created_at),
            messages = CASE WHEN v_quick_reply IS NULL THEN
            COALESCE(messages, '') || COALESCE(v_messages, '')
          ELSE COALESCE(messages, '')
          END,
          quick_replies = CASE WHEN v_quick_replies IS NOT NULL THEN
          (SELECT ARRAY_AGG(DISTINCT qr)
            FROM UNNEST(ARRAY_CAT(quick_replies, v_quick_replies)) as qr)
        ELSE
          quick_replies
        END
        WHERE fb_context_recipient_id = NEW.fb_context_recipient_id;
          END IF;
      END IF;
      RETURN NEW;
  END;
  $$;


  ALTER FUNCTION public.update_facebook_bot_activists_full_text_index() OWNER TO postgres;

  --
  -- Name: verify_custom_domain(); Type: FUNCTION; Schema: public; Owner: postgres
  --

  CREATE FUNCTION verify_custom_domain() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
  BEGIN
    CASE TG_OP
    WHEN 'INSERT' THEN
      IF NEW.custom_domain is not null then
        perform pg_notify('dns_channel', pgjwt.sign(json_build_object(
              'action', 'verify_custom_domain',
              'id', NEW.id,
              'custom_domain', NEW.custom_domain,
              'pg_action', 'insert_custom_domain',
              'sent_to_queuing', now(),
              'jit', now()::timestamp
        ), public.configuration('jwt_secret'), 'HS512'));
      END IF;
      RETURN NEW;

    WHEN 'UPDATE' THEN
      IF NEW.custom_domain is not null then
        perform pg_notify('dns_channel', pgjwt.sign(json_build_object(
              'action', 'verify_custom_domain',
              'id', NEW.id,
              'custom_domain', NEW.custom_domain,
              'pg_action', 'update_custom_domain',
              'sent_to_queuing', now(),
              'jit', now()::timestamp
        ), public.configuration('jwt_secret'), 'HS512'));
      END IF;
      RETURN NEW;

    WHEN 'DELETE' THEN
      perform pg_notify('dns_channel', pgjwt.sign(json_build_object(
            'action', 'verify_custom_domain',
            'id', OLD.id,
            'custom_domain', OLD.custom_domain,
            'pg_action', 'delete_custom_domain',
            'sent_to_queuing', now(),
            'jit', now()::timestamp
      ), public.configuration('jwt_secret'), 'HS512'));
  RETURN OLD;

ELSE
  raise  'custom_domain_not_processed';
    END CASE;
  END;
  $$;


  ALTER FUNCTION public.verify_custom_domain() OWNER TO postgres;

  --
  -- Name: certificates; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE certificates (
    id integer NOT NULL,
    community_id integer,
    mobilization_id integer,
    dns_hosted_zone_id integer,
    domain character varying,
    file_content text,
    expire_on timestamp without time zone,
    is_active boolean,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
  );


  ALTER TABLE certificates OWNER TO postgres;

  SET search_path = microservices, pg_catalog;

  --
  -- Name: certificates; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW certificates AS
  SELECT certificates.id,
  certificates.community_id,
  certificates.mobilization_id,
  certificates.dns_hosted_zone_id AS dns_hosted_zones_id,
  certificates.domain,
  certificates.file_content,
  certificates.expire_on,
  certificates.is_active,
  certificates.created_at,
  certificates.updated_at
  FROM public.certificates
  WHERE ((certificates.is_active IS TRUE) AND (current_user_id() IS NOT NULL));


  ALTER TABLE certificates OWNER TO postgres;

  --
  -- Name: communities; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW communities AS
  SELECT DISTINCT c.id,
  c.name,
  c.city,
  c.created_at,
  c.updated_at,
  c.mailchimp_api_key,
  c.mailchimp_list_id,
  c.mailchimp_group_id,
  c.image,
  c.description,
  c.recipient_id,
  c.facebook_app_id,
  c.fb_link,
  c.twitter_link,
  c.subscription_retry_interval,
  c.subscription_dead_days_interval,
  c.email_template_from,
  c.mailchimp_sync_request_at
  FROM (public.communities c
    RIGHT JOIN public.mobilizations m ON ((c.id = m.community_id)))
  WHERE ((m.custom_domain IS NOT NULL) AND (current_user_id() IS NOT NULL));


  ALTER TABLE communities OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: dns_hosted_zones; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE dns_hosted_zones (
    id integer NOT NULL,
    community_id integer,
    domain_name character varying,
    comment text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    response jsonb,
    ns_ok boolean
  );


  ALTER TABLE dns_hosted_zones OWNER TO postgres;

  SET search_path = microservices, pg_catalog;

  --
  -- Name: dns_hosted_zones; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW dns_hosted_zones AS
  SELECT dns_hosted_zones.id,
  dns_hosted_zones.community_id,
  dns_hosted_zones.domain_name,
  dns_hosted_zones.comment,
  dns_hosted_zones.created_at,
  dns_hosted_zones.updated_at,
  dns_hosted_zones.response,
  dns_hosted_zones.ns_ok
  FROM public.dns_hosted_zones
  WHERE ((dns_hosted_zones.ns_ok IS TRUE) AND (current_user_id() IS NOT NULL));


  ALTER TABLE dns_hosted_zones OWNER TO postgres;

  --
  -- Name: mobilizations; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW mobilizations AS
  SELECT mobilizations.id,
  mobilizations.name,
  mobilizations.created_at,
  mobilizations.updated_at,
  mobilizations.user_id,
  mobilizations.color_scheme,
  mobilizations.google_analytics_code,
  mobilizations.goal,
  mobilizations.header_font,
  mobilizations.body_font,
  mobilizations.facebook_share_title,
  mobilizations.facebook_share_description,
  mobilizations.facebook_share_image,
  mobilizations.slug,
  mobilizations.custom_domain,
  mobilizations.twitter_share_text,
  mobilizations.community_id,
  mobilizations.favicon,
  mobilizations.deleted_at,
  mobilizations.status
  FROM public.mobilizations
  WHERE ((mobilizations.custom_domain IS NOT NULL) AND (current_user_id() IS NOT NULL));


  ALTER TABLE mobilizations OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: notification_templates; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE notification_templates (
    id integer NOT NULL,
    label text NOT NULL,
    community_id integer,
    subject_template text NOT NULL,
    body_template text NOT NULL,
    template_vars jsonb,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    locale text DEFAULT 'pt-BR'::text NOT NULL,
    CONSTRAINT localechk CHECK ((locale = ANY (locale_names())))
  );


  ALTER TABLE notification_templates OWNER TO postgres;

  SET search_path = microservices, pg_catalog;

  --
  -- Name: notification_templates; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW notification_templates AS
  SELECT notification_templates.id,
  notification_templates.label,
  notification_templates.community_id,
  notification_templates.subject_template,
  notification_templates.body_template,
  notification_templates.template_vars,
  notification_templates.created_at,
  notification_templates.updated_at,
  notification_templates.locale
  FROM public.notification_templates
  ORDER BY notification_templates.created_at DESC;


  ALTER TABLE notification_templates OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: notifications; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE notifications (
    id integer NOT NULL,
    activist_id integer,
    notification_template_id integer NOT NULL,
    template_vars jsonb,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    community_id integer,
    user_id integer,
    email character varying,
    deliver_at timestamp without time zone,
    delivered_at timestamp without time zone
  );


  ALTER TABLE notifications OWNER TO postgres;

  SET search_path = microservices, pg_catalog;

  --
  -- Name: notifications; Type: VIEW; Schema: microservices; Owner: postgres
  --

  CREATE VIEW notifications AS
  SELECT notifications.id,
  notifications.activist_id,
  notifications.notification_template_id,
  notifications.template_vars,
  notifications.created_at,
  notifications.updated_at,
  notifications.community_id,
  notifications.user_id,
  notifications.email,
  notifications.deliver_at,
  notifications.delivered_at
  FROM public.notifications
  ORDER BY notifications.created_at DESC;


  ALTER TABLE notifications OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: activist_facebook_bot_interactions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE activist_facebook_bot_interactions (
    id integer NOT NULL,
    activist_id integer,
    facebook_bot_configuration_id integer NOT NULL,
    fb_context_recipient_id text NOT NULL,
    fb_context_sender_id text NOT NULL,
    interaction jsonb NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE activist_facebook_bot_interactions OWNER TO postgres;

  --
  -- Name: facebook_bot_configurations; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE facebook_bot_configurations (
    id integer NOT NULL,
    community_id integer,
    messenger_app_secret text NOT NULL,
    messenger_validation_token text NOT NULL,
    messenger_page_access_token text NOT NULL,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE facebook_bot_configurations OWNER TO postgres;

  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: activist_facebook_bot_interactions; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW activist_facebook_bot_interactions AS
  SELECT i.id,
  i.activist_id,
  i.facebook_bot_configuration_id,
  i.fb_context_recipient_id,
  i.fb_context_sender_id,
  i.interaction,
  i.created_at,
  i.updated_at,
  c.community_id,
  c.data AS facebook_bot_configuration
  FROM (public.activist_facebook_bot_interactions i
    JOIN public.facebook_bot_configurations c ON ((i.facebook_bot_configuration_id = c.id)))
  WHERE current_user_has_community_participation(c.community_id);


  ALTER TABLE activist_facebook_bot_interactions OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: mobilization_activists; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE mobilization_activists (
    id integer NOT NULL,
    mobilization_id integer NOT NULL,
    activist_id integer NOT NULL,
    search_index tsvector,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE mobilization_activists OWNER TO postgres;

  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: activist_mobilizations; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW activist_mobilizations AS
  SELECT ma.activist_id,
  m.id,
  m.name,
  m.created_at,
  m.updated_at,
  m.user_id,
  m.color_scheme,
  m.google_analytics_code,
  m.goal,
  m.header_font,
  m.body_font,
  m.facebook_share_title,
  m.facebook_share_description,
  m.facebook_share_image,
  m.slug,
  m.custom_domain,
  m.twitter_share_text,
  m.community_id,
  m.favicon
  FROM (public.mobilization_activists ma
    JOIN public.mobilizations m ON ((m.id = ma.mobilization_id)))
  WHERE current_user_has_community_participation(m.community_id);


  ALTER TABLE activist_mobilizations OWNER TO postgres;

  --
  -- Name: VIEW activist_mobilizations; Type: COMMENT; Schema: postgraphql; Owner: postgres
  --

  COMMENT ON VIEW activist_mobilizations IS 'show the mobilizations that activists participate';


  --
  -- Name: activist_tags; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW activist_tags AS
  SELECT at.community_id,
  at.activist_id,
  tag.name AS tag_complete_name,
  (regexp_split_to_array((tag.name)::text, '_'::text))[1] AS tag_from,
  replace((regexp_split_to_array((tag.name)::text, '_'::text))[2], '-'::text, ' '::text) AS tag_name,
  tag.label AS tag_label
  FROM ((public.activist_tags at
      JOIN public.taggings tgs ON ((((tgs.taggable_type)::text = 'ActivistTag'::text) AND (tgs.taggable_id = at.id))))
    JOIN public.tags tag ON ((tag.id = tgs.tag_id)))
  WHERE current_user_has_community_participation(at.community_id);


  ALTER TABLE activist_tags OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: balance_operations; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE balance_operations (
    id integer NOT NULL,
    recipient_id integer NOT NULL,
    gateway_data jsonb NOT NULL,
    gateway_id bigint NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE balance_operations OWNER TO postgres;

  --
  -- Name: recipients; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE recipients (
    id integer NOT NULL,
    pagarme_recipient_id character varying NOT NULL,
    recipient jsonb NOT NULL,
    community_id integer NOT NULL,
    transfer_day integer,
    transfer_enabled boolean DEFAULT false,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE recipients OWNER TO postgres;

  --
  -- Name: balance_operation_summaries; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW balance_operation_summaries AS
  SELECT bo.id,
  bo.recipient_id,
  r.community_id,
  (bo.gateway_data ->> 'type'::text) AS operation_type,
  (bo.gateway_data ->> 'object'::text) AS operation_object,
  (bo.gateway_data ->> 'status'::text) AS operation_status,
  (((bo.gateway_data ->> 'amount'::text))::numeric / 100.0) AS operation_amount,
  (((bo.gateway_data ->> 'balance_amount'::text))::numeric / 100.0) AS balance_amount_at_moment,
  (((bo.gateway_data ->> 'fee'::text))::numeric / 100.0) AS operation_fee,
  ((bo.gateway_data ->> 'date_created'::text))::timestamp without time zone AS operation_created_at,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'id'::text) AS movement_object_id,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'type'::text) AS movement_object_type,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'status'::text) AS movement_object_status,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'object'::text) AS movement_object_object,
  ((((bo.gateway_data -> 'movement_object'::text) ->> 'amount'::text))::numeric / 100.0) AS movement_object_amount,
  ((((bo.gateway_data -> 'movement_object'::text) ->> 'fee'::text))::numeric / 100.0) AS movement_object_fee,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'transaction_id'::text) AS movement_object_transaction_id,
  ((bo.gateway_data -> 'movement_object'::text) ->> 'payment_method'::text) AS movement_object_payment_method,
  (bo.gateway_data -> 'movement_object'::text) AS movement_object
  FROM (balance_operations bo
    JOIN recipients r ON ((r.id = bo.recipient_id)))
  ORDER BY ((bo.gateway_data ->> 'date_created'::text))::timestamp without time zone DESC;


  ALTER TABLE balance_operation_summaries OWNER TO postgres;

  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: balance_operations; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW balance_operations AS
  SELECT bos.id,
  bos.recipient_id,
  bos.community_id,
  bos.operation_type,
  bos.operation_object,
  bos.operation_status,
  bos.operation_amount,
  bos.balance_amount_at_moment,
  bos.operation_fee,
  bos.operation_created_at,
  bos.movement_object_id,
  bos.movement_object_type,
  bos.movement_object_status,
  bos.movement_object_object,
  bos.movement_object_amount,
  bos.movement_object_fee,
  bos.movement_object_transaction_id,
  bos.movement_object_payment_method,
  bos.movement_object
  FROM public.balance_operation_summaries bos
  WHERE current_user_has_community_participation(bos.community_id);


  ALTER TABLE balance_operations OWNER TO postgres;

  --
  -- Name: facebook_activist_interactions; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW facebook_activist_interactions AS
  SELECT activist_facebook_bot_interactions.id,
  activist_facebook_bot_interactions.activist_id,
  activist_facebook_bot_interactions.facebook_bot_configuration_id,
  activist_facebook_bot_interactions.fb_context_recipient_id,
  activist_facebook_bot_interactions.fb_context_sender_id,
  activist_facebook_bot_interactions.interaction,
  activist_facebook_bot_interactions.created_at,
  activist_facebook_bot_interactions.updated_at
  FROM public.activist_facebook_bot_interactions
  WHERE ((activist_facebook_bot_interactions.interaction -> 'is_bot'::text) IS NULL);


  ALTER TABLE facebook_activist_interactions OWNER TO postgres;

  --
  -- Name: bot_recipients; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW bot_recipients AS
  SELECT i.facebook_bot_configuration_id,
  i.fb_context_recipient_id,
  i.fb_context_sender_id,
  i.interaction,
  c.community_id,
  c.data AS facebook_bot_configuration,
  i.created_at
  FROM ((facebook_activist_interactions i
      LEFT JOIN facebook_activist_interactions aux ON (((i.facebook_bot_configuration_id = aux.facebook_bot_configuration_id) AND (i.fb_context_recipient_id = aux.fb_context_recipient_id) AND (i.fb_context_sender_id = aux.fb_context_sender_id) AND (i.id < aux.id))))
    LEFT JOIN public.facebook_bot_configurations c ON ((i.facebook_bot_configuration_id = c.id)))
  WHERE ((aux.id IS NULL) AND current_user_has_community_participation(c.community_id));


  ALTER TABLE bot_recipients OWNER TO postgres;

  --
  -- Name: community_user_roles; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW community_user_roles AS
  SELECT cu.id,
  cu.user_id,
  cu.community_id,
  cu.role,
  cu.created_at,
  cu.updated_at
  FROM public.community_users cu
  WHERE (cu.user_id = current_user_id());


  ALTER TABLE community_user_roles OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: blocks; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE blocks (
    id integer NOT NULL,
    mobilization_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    bg_class character varying,
    "position" integer,
    hidden boolean,
    bg_image text,
    name character varying,
    menu_hidden boolean,
    deleted_at timestamp without time zone
  );


  ALTER TABLE blocks OWNER TO postgres;

  --
  -- Name: payable_transfers; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE payable_transfers (
    id integer NOT NULL,
    transfer_id integer,
    transfer_data jsonb,
    transfer_status text,
    community_id integer NOT NULL,
    amount numeric NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE payable_transfers OWNER TO postgres;

  --
  -- Name: widgets; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE widgets (
    id integer NOT NULL,
    block_id integer,
    settings hstore,
    kind character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    sm_size integer,
    md_size integer,
    lg_size integer,
    mailchimp_segment_id character varying,
    action_community boolean DEFAULT false,
    exported_at timestamp without time zone,
    mailchimp_unique_segment_id character varying,
    mailchimp_recurring_active_segment_id character varying,
    mailchimp_recurring_inactive_segment_id character varying,
    goal numeric(8,2),
    deleted_at timestamp without time zone
  );


  ALTER TABLE widgets OWNER TO postgres;

  --
  -- Name: payable_details; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW payable_details AS
  SELECT o.id AS community_id,
  d.widget_id,
  m.id AS mobilization_id,
  b.id AS block_id,
  d.id AS donation_id,
  d.subscription_id,
  d.transaction_id,
  (dd.value ->> 'id'::text) AS payable_id,
  (((d.amount)::numeric / 100.0))::double precision AS donation_value,
  (((dd.value ->> 'amount'::text))::double precision / (100.0)::double precision) AS payable_value,
  (payable_summary.payable_fee)::double precision AS payable_pagarme_fee,
  CASE
  WHEN (jsonb_array_length(d.payables) > 1) THEN nossas_tx.amount
  ELSE ((((d.amount)::numeric / 100.0) * 0.13))::double precision
  END AS nossas_fee,
  nossas_tx.percent AS percent_tx,
  CASE
  WHEN (jsonb_array_length(d.payables) > 1) THEN ((((dd.value ->> 'amount'::text))::double precision / (100.0)::double precision) - (payable_summary.payable_fee)::double precision)
  ELSE ((((d.amount)::numeric / 100.0))::double precision - ((((d.amount)::numeric / 100.0) * 0.13))::double precision)
  END AS value_without_fee,
  ((dd.value ->> 'date_created'::text))::timestamp without time zone AS payment_date,
  ((dd.value ->> 'payment_date'::text))::timestamp without time zone AS payable_date,
  d.transaction_status AS pagarme_status,
  (dd.value ->> 'status'::text) AS payable_status,
  d.payment_method,
  customer.name,
  customer.email,
  pt.id AS payable_transfer_id,
  pt.transfer_data,
  d.gateway_data,
  d.subscription AS is_subscription,
  (dd.value ->> 'recipient_id'::text) AS recipient_id,
  d.local_subscription_id
  FROM (((((((((communities o
                    JOIN donations d ON (((d.cached_community_id = o.id) AND ((d.transaction_status)::text = 'paid'::text))))
                  LEFT JOIN widgets w ON ((w.id = d.widget_id)))
                LEFT JOIN blocks b ON ((b.id = w.block_id)))
              LEFT JOIN mobilizations m ON ((m.id = b.mobilization_id)))
            LEFT JOIN payable_transfers pt ON ((pt.id = d.payable_transfer_id)))
          LEFT JOIN LATERAL ( SELECT COALESCE((d2.customer -> 'name'::text), (d.customer -> 'name'::text)) AS name,
            COALESCE((d2.customer -> 'email'::text), (d.customer -> 'email'::text)) AS email
            FROM donations d2
            WHERE
            CASE
            WHEN (d.parent_id IS NULL) THEN (d2.id = d.id)
            ELSE (d2.id = d.parent_id)
            END) customer ON (true))
        LEFT JOIN LATERAL ( SELECT data.value
          FROM jsonb_array_elements(d.payables) data(value)) dd ON (true))
      LEFT JOIN LATERAL ( SELECT (((jsonb_array_elements.value ->> 'amount'::text))::double precision / (100.0)::double precision) AS amount,
        ((((jsonb_array_elements.value ->> 'amount'::text))::double precision / (d.amount)::double precision) * (100.0)::double precision) AS percent
        FROM jsonb_array_elements(d.payables) jsonb_array_elements(value)
        WHERE ((jsonb_array_elements.value ->> 'recipient_id'::text) = nossas_recipient_id())) nossas_tx ON (true))
    LEFT JOIN LATERAL ( SELECT td.amount,
      td.payable_fee,
      td.transaction_cost,
      (td.amount - td.payable_fee) AS value_without_fee
      FROM ( SELECT ((((dd.value ->> 'amount'::text))::integer)::numeric / 100.0) AS amount,
        ((((dd.value ->> 'fee'::text))::integer)::numeric / 100.0) AS payable_fee,
        ((((d.gateway_data ->> 'cost'::text))::integer)::numeric / 100.0) AS transaction_cost) td) payable_summary ON (true))
  WHERE ((((dd.value ->> 'type'::text) = 'credit'::text) AND ((dd.value ->> 'object'::text) = 'payable'::text) AND ((dd.value ->> 'recipient_id'::text) IN ( SELECT (r.pagarme_recipient_id)::text AS pagarme_recipient_id
          FROM recipients r
          WHERE (r.community_id = o.id)))) OR (jsonb_array_length(d.payables) = 1));


  ALTER TABLE payable_details OWNER TO postgres;

  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: donations; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW donations AS
  SELECT d.id AS donation_id,
  COALESCE(c.id, d.cached_community_id) AS community_id,
  w.id AS widget_id,
  m.id AS mobilization_id,
  b.id AS block_id,
  d.activist_id,
  d.email AS donation_email,
  (d.amount / 100) AS donation_amount,
  d.local_subscription_id AS subscription_id,
  d.transaction_status,
  COALESCE(((d.gateway_data ->> 'date_created'::text))::timestamp without time zone, d.created_at) AS payment_date,
  pd.payable_date,
  pd.payable_value AS payable_amount,
  pd.payable_status,
  s.status AS subscription_status
  FROM ((((((public.donations d
              JOIN public.widgets w ON ((w.id = d.widget_id)))
            LEFT JOIN public.blocks b ON ((b.id = w.block_id)))
          LEFT JOIN public.mobilizations m ON ((m.id = b.mobilization_id)))
        LEFT JOIN public.communities c ON (((c.id = m.community_id) OR (c.id = d.cached_community_id))))
      LEFT JOIN public.subscriptions s ON ((s.id = d.local_subscription_id)))
    LEFT JOIN public.payable_details pd ON ((pd.donation_id = d.id)))
  WHERE ((d.transaction_id IS NOT NULL) AND (c.id IN ( SELECT community_user_roles.community_id
        FROM community_user_roles)));


  ALTER TABLE donations OWNER TO postgres;

  --
  -- Name: facebook_bot_configurations; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW facebook_bot_configurations AS
  SELECT facebook_bot_configurations.id,
  facebook_bot_configurations.community_id,
  facebook_bot_configurations.messenger_app_secret,
  facebook_bot_configurations.messenger_validation_token,
  facebook_bot_configurations.messenger_page_access_token,
  facebook_bot_configurations.data,
  facebook_bot_configurations.created_at,
  facebook_bot_configurations.updated_at
  FROM public.facebook_bot_configurations
  WHERE ((facebook_bot_configurations.data ->> 'deleted'::text) IS NULL);


  ALTER TABLE facebook_bot_configurations OWNER TO postgres;

  --
  -- Name: facebook_bot_interactions; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW facebook_bot_interactions AS
  SELECT activist_facebook_bot_interactions.id,
  activist_facebook_bot_interactions.activist_id,
  activist_facebook_bot_interactions.facebook_bot_configuration_id,
  activist_facebook_bot_interactions.fb_context_recipient_id,
  activist_facebook_bot_interactions.fb_context_sender_id,
  activist_facebook_bot_interactions.interaction,
  activist_facebook_bot_interactions.created_at,
  activist_facebook_bot_interactions.updated_at
  FROM public.activist_facebook_bot_interactions
  WHERE ((activist_facebook_bot_interactions.interaction -> 'is_bot'::text) = 'true'::jsonb);


  ALTER TABLE facebook_bot_interactions OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: activist_participations; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW activist_participations AS
  SELECT
  NULL::integer AS community_id,
  NULL::integer AS mobilization_id,
  NULL::integer AS widget_id,
  NULL::integer AS activist_id,
  NULL::character varying AS email,
  NULL::timestamp without time zone AS participate_at,
  NULL::text AS participate_kind,
  NULL::integer AS participate_id;


  ALTER TABLE activist_participations OWNER TO postgres;

  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: participations; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW participations AS
  SELECT ap.community_id,
  ap.mobilization_id,
  ap.widget_id,
  ap.activist_id,
  ap.email,
  ap.participate_at,
  ap.participate_kind,
  ap.participate_id
  FROM public.activist_participations ap
  WHERE (ap.community_id IN ( SELECT community_user_roles.community_id
      FROM community_user_roles));


  ALTER TABLE participations OWNER TO postgres;

  --
  -- Name: tags; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW tags AS
  SELECT t.id,
  t.name,
  t.taggings_count,
  t.label,
  (regexp_split_to_array((t.name)::text, '_'::text))[1] AS tag_type
  FROM public.tags t;


  ALTER TABLE tags OWNER TO postgres;

  --
  -- Name: user_communities; Type: VIEW; Schema: postgraphql; Owner: postgres
  --

  CREATE VIEW user_communities AS
  SELECT com.id,
  com.name,
  com.city,
  com.description,
  com.created_at,
  com.updated_at,
  com.mailchimp_api_key,
  com.mailchimp_list_id,
  com.mailchimp_group_id,
  com.image,
  com.recipient_id,
  com.facebook_app_id,
  com.fb_link,
  com.twitter_link,
  com.subscription_retry_interval,
  com.subscription_dead_days_interval,
  com.email_template_from,
  com.mailchimp_sync_request_at
  FROM (public.communities com
    JOIN public.community_users cou ON ((cou.community_id = com.id)))
  WHERE (cou.user_id = current_user_id());


  ALTER TABLE user_communities OWNER TO postgres;

  SET search_path = public, pg_catalog;

  --
  -- Name: activist_actions; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW activist_actions AS
  SELECT t.action,
  t.widget_id,
  t.mobilization_id,
  t.community_id,
  t.activist_id,
  t.action_created_date,
  t.activist_created_at,
  t.activist_email
  FROM ( SELECT 'form_entries'::text AS action,
    w.id AS widget_id,
    m.id AS mobilization_id,
    m.community_id,
    fe.activist_id,
    fe.created_at AS action_created_date,
    a.created_at AS activist_created_at,
    a.email AS activist_email
    FROM ((((form_entries fe
            JOIN activists a ON ((a.id = fe.activist_id)))
          JOIN widgets w ON ((w.id = fe.widget_id)))
        JOIN blocks b ON ((b.id = w.block_id)))
      JOIN mobilizations m ON ((m.id = b.mobilization_id)))
    UNION ALL
    SELECT 'activist_pressures'::text AS action,
    w.id AS widget_id,
    m.id AS mobilization_id,
    m.community_id,
    ap.activist_id,
    ap.created_at AS action_created_date,
    a.created_at AS activist_created_at,
    a.email AS activist_email
    FROM ((((activist_pressures ap
            JOIN activists a ON ((a.id = ap.activist_id)))
          JOIN widgets w ON ((w.id = ap.widget_id)))
        JOIN blocks b ON ((b.id = w.block_id)))
      JOIN mobilizations m ON ((m.id = b.mobilization_id)))
    UNION ALL
    SELECT 'donation'::text AS action,
    w.id AS widget_id,
    m.id AS mobilization_id,
    m.community_id,
    d.activist_id,
    d.created_at AS action_created_date,
    a.created_at AS activist_created_at,
    a.email AS activist_email
    FROM ((((donations d
            JOIN activists a ON ((a.id = d.activist_id)))
          JOIN widgets w ON ((w.id = d.widget_id)))
        JOIN blocks b ON ((b.id = w.block_id)))
      JOIN mobilizations m ON ((m.id = b.mobilization_id)))) t;


  ALTER TABLE activist_actions OWNER TO postgres;

  --
  -- Name: activist_facebook_bot_interactions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE activist_facebook_bot_interactions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE activist_facebook_bot_interactions_id_seq OWNER TO postgres;

  --
  -- Name: activist_facebook_bot_interactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE activist_facebook_bot_interactions_id_seq OWNED BY activist_facebook_bot_interactions.id;


  --
  -- Name: activist_matches; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE activist_matches (
    id integer NOT NULL,
    activist_id integer,
    match_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    synchronized boolean,
    mailchimp_syncronization_at timestamp without time zone,
    mailchimp_syncronization_error_reason text
  );


  ALTER TABLE activist_matches OWNER TO postgres;

  --
  -- Name: activist_matches_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE activist_matches_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE activist_matches_id_seq OWNER TO postgres;

  --
  -- Name: activist_matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE activist_matches_id_seq OWNED BY activist_matches.id;


  --
  -- Name: activist_pressures_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE activist_pressures_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE activist_pressures_id_seq OWNER TO postgres;

  --
  -- Name: activist_pressures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE activist_pressures_id_seq OWNED BY activist_pressures.id;


  --
  -- Name: activist_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE activist_tags_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE activist_tags_id_seq OWNER TO postgres;

  --
  -- Name: activist_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE activist_tags_id_seq OWNED BY activist_tags.id;


  --
  -- Name: activists_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE activists_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE activists_id_seq OWNER TO postgres;

  --
  -- Name: activists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE activists_id_seq OWNED BY activists.id;


  --
  -- Name: addresses; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE addresses (
    id integer NOT NULL,
    zipcode character varying,
    street character varying,
    street_number character varying,
    complementary character varying,
    neighborhood character varying,
    city character varying,
    state character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    activist_id integer
  );


  ALTER TABLE addresses OWNER TO postgres;

  --
  -- Name: addresses_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE addresses_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE addresses_id_seq OWNER TO postgres;

  --
  -- Name: addresses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE addresses_id_seq OWNED BY addresses.id;


  --
  -- Name: agg_activists; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW agg_activists AS
  SELECT
  NULL::integer AS community_id,
  NULL::integer AS activist_id,
  NULL::character varying AS email,
  NULL::character varying AS name,
  NULL::text AS phone,
  NULL::bigint AS total_form_entries,
  NULL::bigint AS total_donations,
  NULL::bigint AS total_pressures,
  NULL::bigint AS total_actions,
  NULL::character varying AS last_donation_status,
  NULL::integer AS last_donation_amount,
  NULL::boolean AS last_donation_is_subscription,
  NULL::text AS address_street,
  NULL::text AS street_number,
  NULL::text AS neighborhood,
  NULL::text AS complementary,
  NULL::text AS city,
  NULL::text AS state;


  ALTER TABLE agg_activists OWNER TO postgres;

  --
  -- Name: balance_operations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE balance_operations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE balance_operations_id_seq OWNER TO postgres;

  --
  -- Name: balance_operations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE balance_operations_id_seq OWNED BY balance_operations.id;


  --
  -- Name: blocks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE blocks_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE blocks_id_seq OWNER TO postgres;

  --
  -- Name: blocks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE blocks_id_seq OWNED BY blocks.id;


  --
  -- Name: certificates_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE certificates_id_seq
  AS integer
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE certificates_id_seq OWNER TO postgres;

  --
  -- Name: certificates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE certificates_id_seq OWNED BY certificates.id;


  --
  -- Name: communities_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE communities_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE communities_id_seq OWNER TO postgres;

  --
  -- Name: communities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE communities_id_seq OWNED BY communities.id;


  --
  -- Name: community_activists_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE community_activists_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE community_activists_id_seq OWNER TO postgres;

  --
  -- Name: community_activists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE community_activists_id_seq OWNED BY community_activists.id;


  --
  -- Name: community_users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE community_users_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE community_users_id_seq OWNER TO postgres;

  --
  -- Name: community_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE community_users_id_seq OWNED BY community_users.id;


  --
  -- Name: configurations; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE configurations (
    id integer NOT NULL,
    name character varying NOT NULL,
    value text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE configurations OWNER TO postgres;

  --
  -- Name: configurations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE configurations_id_seq
  AS integer
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE configurations_id_seq OWNER TO postgres;

  --
  -- Name: configurations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE configurations_id_seq OWNED BY configurations.id;


  --
  -- Name: credit_cards; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE credit_cards (
    id integer NOT NULL,
    activist_id integer,
    last_digits character varying,
    card_brand character varying,
    card_id character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    expiration_date character varying
  );


  ALTER TABLE credit_cards OWNER TO postgres;

  --
  -- Name: credit_cards_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE credit_cards_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE credit_cards_id_seq OWNER TO postgres;

  --
  -- Name: credit_cards_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE credit_cards_id_seq OWNED BY credit_cards.id;


  --
  -- Name: dns_hosted_zones_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE dns_hosted_zones_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE dns_hosted_zones_id_seq OWNER TO postgres;

  --
  -- Name: dns_hosted_zones_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE dns_hosted_zones_id_seq OWNED BY dns_hosted_zones.id;


  --
  -- Name: dns_records; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE dns_records (
    id integer NOT NULL,
    dns_hosted_zone_id integer,
    name character varying,
    record_type character varying,
    value text,
    ttl integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    comment character varying
  );


  ALTER TABLE dns_records OWNER TO postgres;

  --
  -- Name: dns_records_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE dns_records_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE dns_records_id_seq OWNER TO postgres;

  --
  -- Name: dns_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE dns_records_id_seq OWNED BY dns_records.id;


  --
  -- Name: donation_reports; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW donation_reports AS
  SELECT m.id AS mobilization_id,
  w.id AS widget_id,
  c.id AS community_id,
  d.id,
  d.transaction_id,
  d.transaction_status AS status,
  to_char(d.created_at, 'dd/mm/YYYY'::text) AS data,
  COALESCE((d.customer -> 'name'::text), (a.name)::text) AS nome,
  d.email,
  COALESCE(customer_phone.number, activist_phone.number) AS telefone,
  d.payment_method AS "cartao/boleto",
  CASE
  WHEN (d.subscription OR (d.local_subscription_id IS NOT NULL)) THEN 'Sim'::text
  ELSE 'Não'::text
  END AS recorrente,
  (((d.amount)::numeric / 100.0))::double precision AS valor,
  pd.value_without_fee AS "valor garantido",
  to_char(((d.gateway_data ->> 'boleto_expiration_date'::text))::timestamp without time zone, 'dd/mm/YYYY'::text) AS "data vencimento boleto",
  recurrency_donation.count AS "recorrencia da doacao",
  recurrency_activist.count AS "recorrencia do ativista",
  (gs.status)::text AS subscription_status,
  pd.payable_date AS "data de recebimento"
  FROM (((((((((((donations d
                        JOIN widgets w ON ((w.id = d.widget_id)))
                      JOIN blocks b ON ((b.id = w.block_id)))
                    JOIN mobilizations m ON ((m.id = b.mobilization_id)))
                  JOIN communities c ON ((c.id = m.community_id)))
                LEFT JOIN subscriptions gs ON ((gs.id = d.local_subscription_id)))
              LEFT JOIN payable_details pd ON ((pd.donation_id = d.id)))
            LEFT JOIN activists a ON ((a.id = d.activist_id)))
          LEFT JOIN LATERAL ( SELECT (((btrim(btrim((d.customer -> 'phone'::text)), '{}'::text))::hstore -> 'ddd'::text) || ((btrim(btrim((d.customer -> 'phone'::text)), '{}'::text))::hstore -> 'number'::text)) AS number) customer_phone ON (true))
        LEFT JOIN LATERAL ( SELECT (((btrim((a.phone)::text, '{}'::text))::hstore -> 'ddd'::text) || ((btrim((a.phone)::text, '{}'::text))::hstore -> 'number'::text)) AS number) activist_phone ON (true))
      LEFT JOIN LATERAL ( SELECT count(1) AS count
        FROM donations d2
        WHERE ((d2.local_subscription_id IS NOT NULL) AND (d2.local_subscription_id = d.local_subscription_id))) recurrency_donation ON (true))
    LEFT JOIN LATERAL ( SELECT count(1) AS count
      FROM donations d2
      WHERE ((d2.activist_id = d.activist_id) AND (d2.cached_community_id = d.cached_community_id) AND (d.activist_id IS NOT NULL))) recurrency_activist ON (true))
  WHERE (d.transaction_id IS NOT NULL);


  ALTER TABLE donation_reports OWNER TO postgres;

  --
  -- Name: donation_transitions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE donation_transitions (
    id integer NOT NULL,
    to_state character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    sort_key integer NOT NULL,
    donation_id integer NOT NULL,
    most_recent boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE donation_transitions OWNER TO postgres;

  --
  -- Name: donation_transitions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE donation_transitions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE donation_transitions_id_seq OWNER TO postgres;

  --
  -- Name: donation_transitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE donation_transitions_id_seq OWNED BY donation_transitions.id;


  --
  -- Name: donations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE donations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE donations_id_seq OWNER TO postgres;

  --
  -- Name: donations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE donations_id_seq OWNED BY donations.id;


  --
  -- Name: facebook_bot_activists; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE facebook_bot_activists (
    id integer NOT NULL,
    fb_context_recipient_id text NOT NULL,
    fb_context_sender_id text NOT NULL,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    messages tsvector,
    quick_replies text[] DEFAULT '{}'::text[],
    interaction_dates timestamp without time zone[] DEFAULT '{}'::timestamp without time zone[],
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE facebook_bot_activists OWNER TO postgres;

  --
  -- Name: facebook_bot_activists_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE facebook_bot_activists_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE facebook_bot_activists_id_seq OWNER TO postgres;

  --
  -- Name: facebook_bot_activists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE facebook_bot_activists_id_seq OWNED BY facebook_bot_activists.id;


  --
  -- Name: facebook_bot_campaign_activists_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE facebook_bot_campaign_activists_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE facebook_bot_campaign_activists_id_seq OWNER TO postgres;

  --
  -- Name: facebook_bot_campaign_activists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE facebook_bot_campaign_activists_id_seq OWNED BY facebook_bot_campaign_activists.id;


  --
  -- Name: facebook_bot_campaigns_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE facebook_bot_campaigns_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE facebook_bot_campaigns_id_seq OWNER TO postgres;

  --
  -- Name: facebook_bot_campaigns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE facebook_bot_campaigns_id_seq OWNED BY facebook_bot_campaigns.id;


  --
  -- Name: facebook_bot_configurations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE facebook_bot_configurations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE facebook_bot_configurations_id_seq OWNER TO postgres;

  --
  -- Name: facebook_bot_configurations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE facebook_bot_configurations_id_seq OWNED BY facebook_bot_configurations.id;


  --
  -- Name: first_email_ids_activists; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW first_email_ids_activists AS
  SELECT min(activists.id) AS min_id,
  lower((activists.email)::text) AS email,
  array_agg(activists.id) AS ids
  FROM activists
  GROUP BY activists.email;


  ALTER TABLE first_email_ids_activists OWNER TO postgres;

  --
  -- Name: form_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE form_entries_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE form_entries_id_seq OWNER TO postgres;

  --
  -- Name: form_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE form_entries_id_seq OWNED BY form_entries.id;


  --
  -- Name: gateway_subscriptions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE gateway_subscriptions (
    id integer NOT NULL,
    subscription_id integer,
    gateway_data jsonb,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE gateway_subscriptions OWNER TO postgres;

  --
  -- Name: gateway_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE gateway_subscriptions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE gateway_subscriptions_id_seq OWNER TO postgres;

  --
  -- Name: gateway_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE gateway_subscriptions_id_seq OWNED BY gateway_subscriptions.id;


  --
  -- Name: gateway_transactions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE gateway_transactions (
    id integer NOT NULL,
    transaction_id text,
    gateway_data jsonb,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE gateway_transactions OWNER TO postgres;

  --
  -- Name: gateway_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE gateway_transactions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE gateway_transactions_id_seq OWNER TO postgres;

  --
  -- Name: gateway_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE gateway_transactions_id_seq OWNED BY gateway_transactions.id;


  --
  -- Name: invitations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE invitations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE invitations_id_seq OWNER TO postgres;

  --
  -- Name: invitations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE invitations_id_seq OWNED BY invitations.id;


  --
  -- Name: matches; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE matches (
    id integer NOT NULL,
    widget_id integer,
    first_choice character varying,
    second_choice character varying,
    goal_image character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE matches OWNER TO postgres;

  --
  -- Name: matches_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE matches_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE matches_id_seq OWNER TO postgres;

  --
  -- Name: matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE matches_id_seq OWNED BY matches.id;


  --
  -- Name: mobilization_activists_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE mobilization_activists_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE mobilization_activists_id_seq OWNER TO postgres;

  --
  -- Name: mobilization_activists_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE mobilization_activists_id_seq OWNED BY mobilization_activists.id;


  --
  -- Name: mobilizations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE mobilizations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE mobilizations_id_seq OWNER TO postgres;

  --
  -- Name: mobilizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE mobilizations_id_seq OWNED BY mobilizations.id;


  --
  -- Name: notification_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE notification_templates_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE notification_templates_id_seq OWNER TO postgres;

  --
  -- Name: notification_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE notification_templates_id_seq OWNED BY notification_templates.id;


  --
  -- Name: notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE notifications_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE notifications_id_seq OWNER TO postgres;

  --
  -- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE notifications_id_seq OWNED BY notifications.id;


  --
  -- Name: payable_transfers_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE payable_transfers_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE payable_transfers_id_seq OWNER TO postgres;

  --
  -- Name: payable_transfers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE payable_transfers_id_seq OWNED BY payable_transfers.id;


  --
  -- Name: payments; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE payments (
    id integer NOT NULL,
    transaction_status character varying,
    transaction_id character varying,
    plan_id integer,
    donation_id integer,
    subscription_id character varying,
    activist_id integer,
    address_id integer,
    credit_card_id integer,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
  );


  ALTER TABLE payments OWNER TO postgres;

  --
  -- Name: payments_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE payments_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE payments_id_seq OWNER TO postgres;

  --
  -- Name: payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE payments_id_seq OWNED BY payments.id;


  --
  -- Name: plans; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE plans (
    id integer NOT NULL,
    plan_id character varying,
    name character varying,
    amount integer,
    days integer,
    payment_methods text[] DEFAULT '{credit_card,boleto}'::text[],
    created_at timestamp without time zone,
    updated_at timestamp without time zone
  );


  ALTER TABLE plans OWNER TO postgres;

  --
  -- Name: plans_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE plans_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE plans_id_seq OWNER TO postgres;

  --
  -- Name: plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE plans_id_seq OWNED BY plans.id;


  --
  -- Name: recipients_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE recipients_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE recipients_id_seq OWNER TO postgres;

  --
  -- Name: recipients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE recipients_id_seq OWNED BY recipients.id;

  --
  -- Name: subscription_transitions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE subscription_transitions (
    id integer NOT NULL,
    to_state character varying NOT NULL,
    metadata json DEFAULT '{}'::json,
    sort_key integer NOT NULL,
    subscription_id integer NOT NULL,
    most_recent boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE subscription_transitions OWNER TO postgres;

  --
  -- Name: subscription_reports; Type: VIEW; Schema: public; Owner: postgres
  --

  CREATE VIEW subscription_reports AS
  SELECT s.community_id,
  a.name AS "Nome do doador",
  a.email AS "Email do doador",
  (((s.amount)::numeric / 100.0))::numeric(13,2) AS "Valor de doação",
  s.status AS "Status de assinatura",
  s.payment_method AS "Forma de doação (boleto/cartão)",
  s.id AS "ID da assinatura",
  s.created_at AS "Data de início da assinatura",
  CASE
  WHEN ((s.status)::text = 'canceled'::text) THEN ct.created_at
  ELSE NULL::timestamp without time zone
  END AS "Data do cancelamento da assinatura",
  CASE
  WHEN ((s.status)::text = 'unpaid'::text) THEN
    CASE
    WHEN receiving_unpaid_notifications(s.*) THEN 'Sim'::text
    ELSE 'Não'::text
    END
  ELSE NULL::text
  END AS "recebendo notificações?",
  ((('https://app.bonde.org/subscriptions/'::text || s.id) || '/edit?token='::text) || s.token) AS "Link de alteração da assinatura"
  FROM (((subscriptions s
        JOIN activists a ON ((a.id = s.activist_id)))
      LEFT JOIN LATERAL ( SELECT st.id,
        st.to_state,
        st.metadata,
        st.sort_key,
        st.subscription_id,
        st.most_recent,
        st.created_at,
        st.updated_at
        FROM subscription_transitions st
        WHERE ((st.subscription_id = s.id) AND ((st.to_state)::text = 'canceled'::text))
        ORDER BY st.created_at DESC
        LIMIT 1) ct ON (true))
    LEFT JOIN LATERAL ( SELECT n.id,
      n.activist_id,
      n.notification_template_id,
      n.template_vars,
      n.created_at,
      n.updated_at,
      n.community_id,
      n.user_id,
      n.email,
      n.deliver_at,
      n.delivered_at
      FROM (notifications n
        JOIN notification_templates nt ON ((nt.id = n.notification_template_id)))
      WHERE ((nt.label = 'unpaid_subscription'::text) AND (((n.template_vars ->> 'subscription_id'::text))::integer = s.id))
      ORDER BY n.created_at DESC
      LIMIT 1) last_unpaid_notification ON (true));


  ALTER TABLE subscription_reports OWNER TO postgres;

  --
  -- Name: subscription_transitions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE subscription_transitions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE subscription_transitions_id_seq OWNER TO postgres;

  --
  -- Name: subscription_transitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE subscription_transitions_id_seq OWNED BY subscription_transitions.id;


  --
  -- Name: subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE subscriptions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE subscriptions_id_seq OWNER TO postgres;

  --
  -- Name: subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE subscriptions_id_seq OWNED BY subscriptions.id;


  --
  -- Name: taggings_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE taggings_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE taggings_id_seq OWNER TO postgres;

  --
  -- Name: taggings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE taggings_id_seq OWNED BY taggings.id;


  --
  -- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE tags_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE tags_id_seq OWNER TO postgres;

  --
  -- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE tags_id_seq OWNED BY tags.id;


  --
  -- Name: template_blocks; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE template_blocks (
    id integer NOT NULL,
    template_mobilization_id integer,
    bg_class character varying,
    "position" integer,
    hidden boolean,
    bg_image text,
    name character varying,
    menu_hidden boolean,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE template_blocks OWNER TO postgres;

  --
  -- Name: template_blocks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE template_blocks_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE template_blocks_id_seq OWNER TO postgres;

  --
  -- Name: template_blocks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE template_blocks_id_seq OWNED BY template_blocks.id;


  --
  -- Name: template_mobilizations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE template_mobilizations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE template_mobilizations_id_seq OWNER TO postgres;

  --
  -- Name: template_mobilizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE template_mobilizations_id_seq OWNED BY template_mobilizations.id;


  --
  -- Name: template_widgets; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE template_widgets (
    id integer NOT NULL,
    template_block_id integer,
    settings hstore,
    kind character varying,
    sm_size integer,
    md_size integer,
    lg_size integer,
    mailchimp_segment_id character varying,
    action_community boolean,
    exported_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE template_widgets OWNER TO postgres;

  --
  -- Name: template_widgets_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE template_widgets_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE template_widgets_id_seq OWNER TO postgres;

  --
  -- Name: template_widgets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE template_widgets_id_seq OWNED BY template_widgets.id;


  --
  -- Name: twilio_call_transitions; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE twilio_call_transitions (
    id integer NOT NULL,
    twilio_account_sid text NOT NULL,
    twilio_call_sid text NOT NULL,
    twilio_parent_call_sid text,
    sequence_number integer NOT NULL,
    status text NOT NULL,
    called text NOT NULL,
    caller text NOT NULL,
    call_duration text,
    data text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE twilio_call_transitions OWNER TO postgres;

  --
  -- Name: twilio_call_transitions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE twilio_call_transitions_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE twilio_call_transitions_id_seq OWNER TO postgres;

  --
  -- Name: twilio_call_transitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE twilio_call_transitions_id_seq OWNED BY twilio_call_transitions.id;


  --
  -- Name: twilio_calls_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE twilio_calls_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE twilio_calls_id_seq OWNER TO postgres;

  --
  -- Name: twilio_calls_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE twilio_calls_id_seq OWNED BY twilio_calls.id;


  --
  -- Name: twilio_configurations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE twilio_configurations_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE twilio_configurations_id_seq OWNER TO postgres;

  --
  -- Name: twilio_configurations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE twilio_configurations_id_seq OWNED BY twilio_configurations.id;


  --
  -- Name: user_tags; Type: TABLE; Schema: public; Owner: postgres
  --

  CREATE TABLE user_tags (
    id integer NOT NULL,
    user_id integer,
    tag_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
  );


  ALTER TABLE user_tags OWNER TO postgres;

  --
  -- Name: user_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE user_tags_id_seq
  AS integer
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE user_tags_id_seq OWNER TO postgres;

  --
  -- Name: user_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE user_tags_id_seq OWNED BY user_tags.id;


  --
  -- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE users_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE users_id_seq OWNER TO postgres;

  --
  -- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE users_id_seq OWNED BY users.id;


  --
  -- Name: widgets_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
  --

  CREATE SEQUENCE widgets_id_seq
  START WITH 1
  INCREMENT BY 1
  NO MINVALUE
  NO MAXVALUE
  CACHE 1;


  ALTER TABLE widgets_id_seq OWNER TO postgres;

  --
  -- Name: widgets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
  --

  ALTER SEQUENCE widgets_id_seq OWNED BY widgets.id;


  --
  -- Name: activist_facebook_bot_interactions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_facebook_bot_interactions ALTER COLUMN id SET DEFAULT nextval('activist_facebook_bot_interactions_id_seq'::regclass);


  --
  -- Name: activist_matches id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_matches ALTER COLUMN id SET DEFAULT nextval('activist_matches_id_seq'::regclass);


  --
  -- Name: activist_pressures id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_pressures ALTER COLUMN id SET DEFAULT nextval('activist_pressures_id_seq'::regclass);


  --
  -- Name: activist_tags id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_tags ALTER COLUMN id SET DEFAULT nextval('activist_tags_id_seq'::regclass);


  --
  -- Name: activists id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activists ALTER COLUMN id SET DEFAULT nextval('activists_id_seq'::regclass);


  --
  -- Name: addresses id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY addresses ALTER COLUMN id SET DEFAULT nextval('addresses_id_seq'::regclass);


  --
  -- Name: balance_operations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY balance_operations ALTER COLUMN id SET DEFAULT nextval('balance_operations_id_seq'::regclass);


  --
  -- Name: blocks id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY blocks ALTER COLUMN id SET DEFAULT nextval('blocks_id_seq'::regclass);


  --
  -- Name: certificates id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY certificates ALTER COLUMN id SET DEFAULT nextval('certificates_id_seq'::regclass);


  --
  -- Name: communities id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY communities ALTER COLUMN id SET DEFAULT nextval('communities_id_seq'::regclass);


  --
  -- Name: community_activists id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_activists ALTER COLUMN id SET DEFAULT nextval('community_activists_id_seq'::regclass);


  --
  -- Name: community_users id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_users ALTER COLUMN id SET DEFAULT nextval('community_users_id_seq'::regclass);


  --
  -- Name: configurations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY configurations ALTER COLUMN id SET DEFAULT nextval('configurations_id_seq'::regclass);


  --
  -- Name: credit_cards id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY credit_cards ALTER COLUMN id SET DEFAULT nextval('credit_cards_id_seq'::regclass);


  --
  -- Name: dns_hosted_zones id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_hosted_zones ALTER COLUMN id SET DEFAULT nextval('dns_hosted_zones_id_seq'::regclass);


  --
  -- Name: dns_records id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_records ALTER COLUMN id SET DEFAULT nextval('dns_records_id_seq'::regclass);


  --
  -- Name: donation_transitions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donation_transitions ALTER COLUMN id SET DEFAULT nextval('donation_transitions_id_seq'::regclass);


  --
  -- Name: donations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations ALTER COLUMN id SET DEFAULT nextval('donations_id_seq'::regclass);


  --
  -- Name: facebook_bot_activists id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_activists ALTER COLUMN id SET DEFAULT nextval('facebook_bot_activists_id_seq'::regclass);


  --
  -- Name: facebook_bot_campaign_activists id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaign_activists ALTER COLUMN id SET DEFAULT nextval('facebook_bot_campaign_activists_id_seq'::regclass);


  --
  -- Name: facebook_bot_campaigns id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaigns ALTER COLUMN id SET DEFAULT nextval('facebook_bot_campaigns_id_seq'::regclass);


  --
  -- Name: facebook_bot_configurations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_configurations ALTER COLUMN id SET DEFAULT nextval('facebook_bot_configurations_id_seq'::regclass);


  --
  -- Name: form_entries id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY form_entries ALTER COLUMN id SET DEFAULT nextval('form_entries_id_seq'::regclass);


  --
  -- Name: gateway_subscriptions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY gateway_subscriptions ALTER COLUMN id SET DEFAULT nextval('gateway_subscriptions_id_seq'::regclass);


  --
  -- Name: gateway_transactions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY gateway_transactions ALTER COLUMN id SET DEFAULT nextval('gateway_transactions_id_seq'::regclass);


  --
  -- Name: invitations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY invitations ALTER COLUMN id SET DEFAULT nextval('invitations_id_seq'::regclass);


  --
  -- Name: matches id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY matches ALTER COLUMN id SET DEFAULT nextval('matches_id_seq'::regclass);


  --
  -- Name: mobilization_activists id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilization_activists ALTER COLUMN id SET DEFAULT nextval('mobilization_activists_id_seq'::regclass);


  --
  -- Name: mobilizations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilizations ALTER COLUMN id SET DEFAULT nextval('mobilizations_id_seq'::regclass);


  --
  -- Name: notification_templates id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notification_templates ALTER COLUMN id SET DEFAULT nextval('notification_templates_id_seq'::regclass);


  --
  -- Name: notifications id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications ALTER COLUMN id SET DEFAULT nextval('notifications_id_seq'::regclass);


  --
  -- Name: payable_transfers id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY payable_transfers ALTER COLUMN id SET DEFAULT nextval('payable_transfers_id_seq'::regclass);


  --
  -- Name: payments id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY payments ALTER COLUMN id SET DEFAULT nextval('payments_id_seq'::regclass);


  --
  -- Name: plans id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY plans ALTER COLUMN id SET DEFAULT nextval('plans_id_seq'::regclass);


  --
  -- Name: recipients id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY recipients ALTER COLUMN id SET DEFAULT nextval('recipients_id_seq'::regclass);


  --
  -- Name: subscription_transitions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscription_transitions ALTER COLUMN id SET DEFAULT nextval('subscription_transitions_id_seq'::regclass);


  --
  -- Name: subscriptions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions ALTER COLUMN id SET DEFAULT nextval('subscriptions_id_seq'::regclass);


  --
  -- Name: taggings id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY taggings ALTER COLUMN id SET DEFAULT nextval('taggings_id_seq'::regclass);


  --
  -- Name: tags id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY tags ALTER COLUMN id SET DEFAULT nextval('tags_id_seq'::regclass);


  --
  -- Name: template_blocks id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_blocks ALTER COLUMN id SET DEFAULT nextval('template_blocks_id_seq'::regclass);


  --
  -- Name: template_mobilizations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_mobilizations ALTER COLUMN id SET DEFAULT nextval('template_mobilizations_id_seq'::regclass);


  --
  -- Name: template_widgets id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_widgets ALTER COLUMN id SET DEFAULT nextval('template_widgets_id_seq'::regclass);


  --
  -- Name: twilio_call_transitions id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_call_transitions ALTER COLUMN id SET DEFAULT nextval('twilio_call_transitions_id_seq'::regclass);


  --
  -- Name: twilio_calls id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_calls ALTER COLUMN id SET DEFAULT nextval('twilio_calls_id_seq'::regclass);


  --
  -- Name: twilio_configurations id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_configurations ALTER COLUMN id SET DEFAULT nextval('twilio_configurations_id_seq'::regclass);


  --
  -- Name: user_tags id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY user_tags ALTER COLUMN id SET DEFAULT nextval('user_tags_id_seq'::regclass);


  --
  -- Name: users id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY users ALTER COLUMN id SET DEFAULT nextval('users_id_seq'::regclass);


  --
  -- Name: widgets id; Type: DEFAULT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY widgets ALTER COLUMN id SET DEFAULT nextval('widgets_id_seq'::regclass);


  --
  -- Name: activist_facebook_bot_interactions activist_facebook_bot_interactions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_facebook_bot_interactions
  ADD CONSTRAINT activist_facebook_bot_interactions_pkey PRIMARY KEY (id);


  --
  -- Name: activist_matches activist_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_matches
  ADD CONSTRAINT activist_matches_pkey PRIMARY KEY (id);


  --
  -- Name: activist_pressures activist_pressures_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_pressures
  ADD CONSTRAINT activist_pressures_pkey PRIMARY KEY (id);


  --
  -- Name: activist_tags activist_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_tags
  ADD CONSTRAINT activist_tags_pkey PRIMARY KEY (id);


  --
  -- Name: activists activists_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activists
  ADD CONSTRAINT activists_pkey PRIMARY KEY (id);


  --
  -- Name: addresses addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY addresses
  ADD CONSTRAINT addresses_pkey PRIMARY KEY (id);


  --
  -- Name: balance_operations balance_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY balance_operations
  ADD CONSTRAINT balance_operations_pkey PRIMARY KEY (id);


  --
  -- Name: blocks blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY blocks
  ADD CONSTRAINT blocks_pkey PRIMARY KEY (id);


  --
  -- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY certificates
  ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


  --
  -- Name: communities communities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY communities
  ADD CONSTRAINT communities_pkey PRIMARY KEY (id);


  --
  -- Name: community_activists community_activists_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_activists
  ADD CONSTRAINT community_activists_pkey PRIMARY KEY (id);


  --
  -- Name: community_users community_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_users
  ADD CONSTRAINT community_users_pkey PRIMARY KEY (id);


  --
  -- Name: configurations configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY configurations
  ADD CONSTRAINT configurations_pkey PRIMARY KEY (id);


  --
  -- Name: credit_cards credit_cards_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY credit_cards
  ADD CONSTRAINT credit_cards_pkey PRIMARY KEY (id);


  --
  -- Name: dns_hosted_zones dns_hosted_zones_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_hosted_zones
  ADD CONSTRAINT dns_hosted_zones_pkey PRIMARY KEY (id);


  --
  -- Name: dns_records dns_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_records
  ADD CONSTRAINT dns_records_pkey PRIMARY KEY (id);


  --
  -- Name: donation_transitions donation_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donation_transitions
  ADD CONSTRAINT donation_transitions_pkey PRIMARY KEY (id);


  --
  -- Name: donations donations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT donations_pkey PRIMARY KEY (id);


  --
  -- Name: facebook_bot_activists facebook_bot_activists_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_activists
  ADD CONSTRAINT facebook_bot_activists_pkey PRIMARY KEY (id);


  --
  -- Name: facebook_bot_campaign_activists facebook_bot_campaign_activists_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaign_activists
  ADD CONSTRAINT facebook_bot_campaign_activists_pkey PRIMARY KEY (id);


  --
  -- Name: facebook_bot_campaigns facebook_bot_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaigns
  ADD CONSTRAINT facebook_bot_campaigns_pkey PRIMARY KEY (id);


  --
  -- Name: facebook_bot_configurations facebook_bot_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_configurations
  ADD CONSTRAINT facebook_bot_configurations_pkey PRIMARY KEY (id);


  --
  -- Name: form_entries form_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY form_entries
  ADD CONSTRAINT form_entries_pkey PRIMARY KEY (id);


  --
  -- Name: gateway_subscriptions gateway_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY gateway_subscriptions
  ADD CONSTRAINT gateway_subscriptions_pkey PRIMARY KEY (id);


  --
  -- Name: gateway_transactions gateway_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY gateway_transactions
  ADD CONSTRAINT gateway_transactions_pkey PRIMARY KEY (id);


  --
  -- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY invitations
  ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


  --
  -- Name: matches matches_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY matches
  ADD CONSTRAINT matches_pkey PRIMARY KEY (id);


  --
  -- Name: mobilization_activists mobilization_activists_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilization_activists
  ADD CONSTRAINT mobilization_activists_pkey PRIMARY KEY (id);


  --
  -- Name: mobilizations mobilizations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilizations
  ADD CONSTRAINT mobilizations_pkey PRIMARY KEY (id);


  --
  -- Name: notification_templates notification_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notification_templates
  ADD CONSTRAINT notification_templates_pkey PRIMARY KEY (id);


  --
  -- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications
  ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


  --
  -- Name: payable_transfers payable_transfers_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY payable_transfers
  ADD CONSTRAINT payable_transfers_pkey PRIMARY KEY (id);


  --
  -- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY payments
  ADD CONSTRAINT payments_pkey PRIMARY KEY (id);


  --
  -- Name: plans plans_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY plans
  ADD CONSTRAINT plans_pkey PRIMARY KEY (id);


  --
  -- Name: recipients recipients_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY recipients
  ADD CONSTRAINT recipients_pkey PRIMARY KEY (id);


  --
  -- Name: subscription_transitions subscription_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscription_transitions
  ADD CONSTRAINT subscription_transitions_pkey PRIMARY KEY (id);


  --
  -- Name: subscriptions subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions
  ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);


  --
  -- Name: taggings taggings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY taggings
  ADD CONSTRAINT taggings_pkey PRIMARY KEY (id);


  --
  -- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY tags
  ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


  --
  -- Name: template_blocks template_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_blocks
  ADD CONSTRAINT template_blocks_pkey PRIMARY KEY (id);


  --
  -- Name: template_mobilizations template_mobilizations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_mobilizations
  ADD CONSTRAINT template_mobilizations_pkey PRIMARY KEY (id);


  --
  -- Name: template_widgets template_widgets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY template_widgets
  ADD CONSTRAINT template_widgets_pkey PRIMARY KEY (id);


  --
  -- Name: twilio_call_transitions twilio_call_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_call_transitions
  ADD CONSTRAINT twilio_call_transitions_pkey PRIMARY KEY (id);


  --
  -- Name: twilio_calls twilio_calls_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_calls
  ADD CONSTRAINT twilio_calls_pkey PRIMARY KEY (id);


  --
  -- Name: twilio_configurations twilio_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_configurations
  ADD CONSTRAINT twilio_configurations_pkey PRIMARY KEY (id);


  --
  -- Name: user_tags user_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY user_tags
  ADD CONSTRAINT user_tags_pkey PRIMARY KEY (id);


  --
  -- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY users
  ADD CONSTRAINT users_pkey PRIMARY KEY (id);


  --
  -- Name: widgets widgets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY widgets
  ADD CONSTRAINT widgets_pkey PRIMARY KEY (id);


  --
  -- Name: ids_blocks_mob_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX ids_blocks_mob_id ON public.blocks USING btree (mobilization_id);


  --
  -- Name: ids_widgets_block_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX ids_widgets_block_id ON public.widgets USING btree (block_id);


  --
  -- Name: ids_widgets_kind; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX ids_widgets_kind ON public.widgets USING btree (kind);


  --
  -- Name: idx_activists_on_bot_interations; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_activists_on_bot_interations ON public.activist_facebook_bot_interactions USING btree (activist_id);


  --
  -- Name: idx_bot_config_on_bot_interactions; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_bot_config_on_bot_interactions ON public.activist_facebook_bot_interactions USING btree (facebook_bot_configuration_id);


  --
  -- Name: idx_facebook_bot_campaign_activists_on_facebook_bot_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_facebook_bot_campaign_activists_on_facebook_bot_activist_id ON public.facebook_bot_campaign_activists USING btree (facebook_bot_activist_id);


  --
  -- Name: idx_facebook_bot_campaign_activists_on_facebook_bot_campaign_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_facebook_bot_campaign_activists_on_facebook_bot_campaign_id ON public.facebook_bot_campaign_activists USING btree (facebook_bot_campaign_id);


  --
  -- Name: idx_form_entries_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_form_entries_activist_id ON public.form_entries USING btree (activist_id);


  --
  -- Name: idx_mobilizations_custom_domain; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_mobilizations_custom_domain ON public.mobilizations USING btree (custom_domain);


  --
  -- Name: idx_mobilizations_slug; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX idx_mobilizations_slug ON public.mobilizations USING btree (slug);


  --
  -- Name: index_activist_matches_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activist_matches_on_activist_id ON public.activist_matches USING btree (activist_id);


  --
  -- Name: index_activist_matches_on_match_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activist_matches_on_match_id ON public.activist_matches USING btree (match_id);


  --
  -- Name: index_activist_pressures_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activist_pressures_on_activist_id ON public.activist_pressures USING btree (activist_id);


  --
  -- Name: index_activist_pressures_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activist_pressures_on_widget_id ON public.activist_pressures USING btree (widget_id);


  --
  -- Name: index_activist_tags_on_activist_id_and_community_id_and_mob_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_activist_tags_on_activist_id_and_community_id_and_mob_id ON public.activist_tags USING btree (activist_id, community_id, mobilization_id);


  --
  -- Name: index_activists_on_created_at; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activists_on_created_at ON public.activists USING btree (created_at DESC);


  --
  -- Name: index_activists_on_email; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_activists_on_email ON public.activists USING btree (email);


  --
  -- Name: index_addresses_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_addresses_on_activist_id ON public.addresses USING btree (activist_id);


  --
  -- Name: index_balance_operations_on_recipient_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_balance_operations_on_recipient_id ON public.balance_operations USING btree (recipient_id);


  --
  -- Name: index_community_activists_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_community_activists_on_activist_id ON public.community_activists USING btree (activist_id);


  --
  -- Name: index_community_activists_on_community_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_community_activists_on_community_id ON public.community_activists USING btree (community_id);


  --
  -- Name: index_community_activists_on_community_id_and_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_community_activists_on_community_id_and_activist_id ON public.community_activists USING btree (community_id, activist_id);


  --
  -- Name: index_configurations_on_name; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_configurations_on_name ON public.configurations USING btree (name);


  --
  -- Name: index_credit_cards_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_credit_cards_on_activist_id ON public.credit_cards USING btree (activist_id);


  --
  -- Name: index_dns_hosted_zones_on_domain_name; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_dns_hosted_zones_on_domain_name ON public.dns_hosted_zones USING btree (domain_name);


  --
  -- Name: index_dns_records_on_name_and_record_type; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_dns_records_on_name_and_record_type ON public.dns_records USING btree (name, record_type);


  --
  -- Name: index_donation_transitions_parent_most_recent; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_donation_transitions_parent_most_recent ON public.donation_transitions USING btree (donation_id, most_recent) WHERE most_recent;


  --
  -- Name: index_donation_transitions_parent_sort; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_donation_transitions_parent_sort ON public.donation_transitions USING btree (donation_id, sort_key);


  --
  -- Name: index_donations_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_donations_on_activist_id ON public.donations USING btree (activist_id);


  --
  -- Name: index_donations_on_customer; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_donations_on_customer ON public.donations USING gin (customer);


  --
  -- Name: index_donations_on_payable_transfer_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_donations_on_payable_transfer_id ON public.donations USING btree (payable_transfer_id);


  --
  -- Name: index_donations_on_transaction_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_donations_on_transaction_id ON public.donations USING btree (transaction_id);


  --
  -- Name: index_donations_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_donations_on_widget_id ON public.donations USING btree (widget_id);


  --
  -- Name: index_facebook_bot_activists_on_interaction_dates; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_facebook_bot_activists_on_interaction_dates ON public.facebook_bot_activists USING btree (interaction_dates);


  --
  -- Name: index_facebook_bot_activists_on_messages; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_facebook_bot_activists_on_messages ON public.facebook_bot_activists USING gin (messages);


  --
  -- Name: index_facebook_bot_activists_on_quick_replies; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_facebook_bot_activists_on_quick_replies ON public.facebook_bot_activists USING btree (quick_replies);


  --
  -- Name: index_facebook_bot_activists_on_recipient_id_and_sender_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_facebook_bot_activists_on_recipient_id_and_sender_id ON public.facebook_bot_activists USING btree (fb_context_recipient_id, fb_context_sender_id);


  --
  -- Name: index_facebook_bot_campaigns_on_facebook_bot_configuration_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_facebook_bot_campaigns_on_facebook_bot_configuration_id ON public.facebook_bot_campaigns USING btree (facebook_bot_configuration_id);


  --
  -- Name: index_form_entries_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_form_entries_on_widget_id ON public.form_entries USING btree (widget_id);


  --
  -- Name: index_gateway_subscriptions_on_subscription_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_gateway_subscriptions_on_subscription_id ON public.gateway_subscriptions USING btree (subscription_id);


  --
  -- Name: index_invitations_on_community_id_and_code; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_invitations_on_community_id_and_code ON public.invitations USING btree (community_id, code);


  --
  -- Name: index_matches_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_matches_on_widget_id ON public.matches USING btree (widget_id);


  --
  -- Name: index_mobilization_activists_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_mobilization_activists_on_activist_id ON public.mobilization_activists USING btree (activist_id);


  --
  -- Name: index_mobilization_activists_on_mobilization_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_mobilization_activists_on_mobilization_id ON public.mobilization_activists USING btree (mobilization_id);


  --
  -- Name: index_mobilization_activists_on_mobilization_id_and_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_mobilization_activists_on_mobilization_id_and_activist_id ON public.mobilization_activists USING btree (mobilization_id, activist_id);


  --
  -- Name: index_mobilizations_on_community_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_mobilizations_on_community_id ON public.mobilizations USING btree (community_id);


  --
  -- Name: index_mobilizations_on_custom_domain; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_mobilizations_on_custom_domain ON public.mobilizations USING btree (custom_domain);


  --
  -- Name: index_mobilizations_on_slug; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_mobilizations_on_slug ON public.mobilizations USING btree (slug);


  --
  -- Name: index_notifications_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_notifications_on_activist_id ON public.notifications USING btree (activist_id);


  --
  -- Name: index_notifications_on_community_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_notifications_on_community_id ON public.notifications USING btree (community_id);


  --
  -- Name: index_notifications_on_notification_template_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_notifications_on_notification_template_id ON public.notifications USING btree (notification_template_id);


  --
  -- Name: index_payments_on_donation_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_payments_on_donation_id ON public.payments USING btree (donation_id);


  --
  -- Name: index_subscription_transitions_parent_most_recent; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_subscription_transitions_parent_most_recent ON public.subscription_transitions USING btree (subscription_id, most_recent) WHERE most_recent;


  --
  -- Name: index_subscription_transitions_parent_sort; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_subscription_transitions_parent_sort ON public.subscription_transitions USING btree (subscription_id, sort_key);


  --
  -- Name: index_subscriptions_on_activist_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_subscriptions_on_activist_id ON public.subscriptions USING btree (activist_id);


  --
  -- Name: index_subscriptions_on_community_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_subscriptions_on_community_id ON public.subscriptions USING btree (community_id);


  --
  -- Name: index_subscriptions_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_subscriptions_on_widget_id ON public.subscriptions USING btree (widget_id);


  --
  -- Name: index_taggings_on_context; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_context ON public.taggings USING btree (context);


  --
  -- Name: index_taggings_on_tag_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_tag_id ON public.taggings USING btree (tag_id);


  --
  -- Name: index_taggings_on_taggable_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_taggable_id ON public.taggings USING btree (taggable_id);


  --
  -- Name: index_taggings_on_taggable_id_and_taggable_type; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_taggable_id_and_taggable_type ON public.taggings USING btree (taggable_id, taggable_type);


  --
  -- Name: index_taggings_on_taggable_id_and_taggable_type_and_context; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_taggable_id_and_taggable_type_and_context ON public.taggings USING btree (taggable_id, taggable_type, context);


  --
  -- Name: index_taggings_on_taggable_type; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_taggable_type ON public.taggings USING btree (taggable_type);


  --
  -- Name: index_taggings_on_tagger_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_tagger_id ON public.taggings USING btree (tagger_id);


  --
  -- Name: index_taggings_on_tagger_id_and_tagger_type; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_taggings_on_tagger_id_and_tagger_type ON public.taggings USING btree (tagger_id, tagger_type);


  --
  -- Name: index_tags_on_name; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_tags_on_name ON public.tags USING btree (name);


  --
  -- Name: index_twilio_calls_on_widget_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_twilio_calls_on_widget_id ON public.twilio_calls USING btree (widget_id);


  --
  -- Name: index_twilio_configurations_on_community_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_twilio_configurations_on_community_id ON public.twilio_configurations USING btree (community_id);


  --
  -- Name: index_user_tags_on_user_id; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_user_tags_on_user_id ON public.user_tags USING btree (user_id);


  --
  -- Name: index_users_on_email; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX index_users_on_email ON public.users USING btree (email);


  --
  -- Name: index_users_on_reset_password_token; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_users_on_reset_password_token ON public.users USING btree (reset_password_token);


  --
  -- Name: index_users_on_uid_and_provider; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX index_users_on_uid_and_provider ON public.users USING btree (uid, provider);


  --
  -- Name: notification_templates_label_uniq_idx; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX notification_templates_label_uniq_idx ON public.notification_templates USING btree (community_id, label, locale);


  --
  -- Name: ordasc_widgets; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX ordasc_widgets ON public.widgets USING btree (id);


  --
  -- Name: taggings_idx; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX taggings_idx ON public.taggings USING btree (tag_id, taggable_id, taggable_type, context, tagger_id, tagger_type);


  --
  -- Name: taggings_idy; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE INDEX taggings_idy ON public.taggings USING btree (taggable_id, taggable_type, tagger_id, context);


  --
  -- Name: uniq_email_acts; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX uniq_email_acts ON public.activists USING btree (lower(((email)::email)::text));


  --
  -- Name: uniq_m_page_access_token_idx; Type: INDEX; Schema: public; Owner: postgres
  --

  CREATE UNIQUE INDEX uniq_m_page_access_token_idx ON public.facebook_bot_configurations USING btree (messenger_page_access_token);


  SET search_path = postgraphql, pg_catalog;

  --
  -- Name: users _RETURN; Type: RULE; Schema: postgraphql; Owner: postgres
  --

  CREATE OR REPLACE VIEW users AS
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
  FROM ((public.users u
      LEFT JOIN public.user_tags ut ON ((ut.user_id = u.id)))
    LEFT JOIN public.tags t ON ((t.id = ut.tag_id)))
  WHERE (u.id = (current_setting('jwt.claims.user_id'::text))::integer)
  GROUP BY u.id;


  SET search_path = public, pg_catalog;

  --
  -- Name: agg_activists _RETURN; Type: RULE; Schema: public; Owner: postgres
  --

  CREATE OR REPLACE VIEW agg_activists AS
  SELECT com.id AS community_id,
  a.id AS activist_id,
  a.email,
  a.name,
  (((btrim((a.phone)::text, '{}'::text))::hstore -> 'ddd'::text) || ((btrim((a.phone)::text, '{}'::text))::hstore -> 'number'::text)) AS phone,
  agg_fe.count AS total_form_entries,
  agg_do.count AS total_donations,
  agg_ap.count AS total_pressures,
  ((agg_fe.count + agg_do.count) + agg_ap.count) AS total_actions,
  last_donation.transaction_status AS last_donation_status,
  (last_donation.amount / 100) AS last_donation_amount,
  last_donation.subscription AS last_donation_is_subscription,
  (last_customer.address -> 'street'::text) AS address_street,
  (last_customer.address -> 'street_number'::text) AS street_number,
  (last_customer.address -> 'neighborhood'::text) AS neighborhood,
  (last_customer.address -> 'complementary'::text) AS complementary,
  (last_customer.address -> 'city'::text) AS city,
  (last_customer.address -> 'state'::text) AS state
  FROM (((((((communities com
                JOIN community_activists cac ON ((cac.community_id = com.id)))
              JOIN activists a ON ((a.id = cac.activist_id)))
            LEFT JOIN LATERAL ( SELECT count(1) AS count
              FROM (((form_entries fe
                    JOIN widgets w ON ((w.id = fe.widget_id)))
                  JOIN blocks b ON ((b.id = w.block_id)))
                JOIN mobilizations m ON ((b.mobilization_id = m.id)))
              WHERE ((fe.activist_id = a.id) AND (m.community_id = com.id))) agg_fe ON (true))
          LEFT JOIN LATERAL ( SELECT count(1) AS count
            FROM (((donations d
                  JOIN widgets w ON ((w.id = d.widget_id)))
                JOIN blocks b ON ((b.id = w.block_id)))
              JOIN mobilizations m ON ((b.mobilization_id = m.id)))
            WHERE (((d.transaction_status)::text = 'paid'::text) AND (d.activist_id = a.id) AND (m.community_id = com.id))) agg_do ON (true))
        LEFT JOIN LATERAL ( SELECT count(1) AS count
          FROM (((activist_pressures ap
                JOIN widgets w ON ((w.id = ap.widget_id)))
              JOIN blocks b ON ((b.id = w.block_id)))
            JOIN mobilizations m ON ((b.mobilization_id = m.id)))
          WHERE ((ap.activist_id = a.id) AND (m.community_id = com.id))) agg_ap ON (true))
      LEFT JOIN LATERAL ( SELECT (btrim((d2.customer -> 'address'::text), '{}'::text))::hstore AS address
        FROM donations d2
        WHERE ((d2.activist_id = a.id) AND (d2.transaction_id IS NOT NULL) AND (d2.transaction_status IS NOT NULL) AND (d2.customer IS NOT NULL))
        ORDER BY d2.id DESC
        LIMIT 1) last_customer ON (true))
    LEFT JOIN LATERAL ( SELECT d2.id,
      d2.widget_id,
      d2.created_at,
      d2.updated_at,
      d2.token,
      d2.payment_method,
      d2.amount,
      d2.email,
      d2.card_hash,
      d2.customer,
      d2.skip,
      d2.transaction_id,
      d2.transaction_status,
      d2.subscription,
      d2.credit_card,
      d2.activist_id,
      d2.subscription_id,
      d2.period,
      d2.plan_id,
      d2.parent_id,
      d2.payables,
      d2.gateway_data,
      d2.payable_transfer_id,
      d2.converted_from
      FROM donations d2
      WHERE ((d2.activist_id = a.id) AND (d2.transaction_id IS NOT NULL) AND (d2.transaction_status IS NOT NULL))
      ORDER BY d2.id DESC
      LIMIT 1) last_donation ON (true))
  WHERE (a.id IS NOT NULL)
  GROUP BY com.id, a.email, a.id, last_donation.transaction_status, last_donation.amount, last_donation.subscription, last_customer.address, agg_fe.count, agg_do.count, agg_ap.count;


  --
  -- Name: activist_participations _RETURN; Type: RULE; Schema: public; Owner: postgres
  --

  CREATE OR REPLACE VIEW activist_participations AS
  SELECT c.id AS community_id,
  m.id AS mobilization_id,
  w.id AS widget_id,
  a.id AS activist_id,
  a.email,
  COALESCE(fe.created_at, d.created_at, ap.created_at, s.created_at) AS participate_at,
  CASE
  WHEN (fe.id IS NOT NULL) THEN 'form_entry'::text
  WHEN ((d.id IS NOT NULL) AND (d.local_subscription_id IS NOT NULL)) THEN 'subscription'::text
  WHEN ((d.id IS NOT NULL) AND (d.local_subscription_id IS NULL)) THEN 'donation'::text
  WHEN (ap.id IS NOT NULL) THEN 'activist_pressure'::text
  WHEN (s.id IS NOT NULL) THEN 'subscription'::text
  ELSE NULL::text
  END AS participate_kind,
  COALESCE(fe.id, d.id, ap.id, s.id) AS participate_id
  FROM ((((((((communities c
                  JOIN mobilizations m ON ((m.community_id = c.id)))
                LEFT JOIN blocks b ON ((b.mobilization_id = m.id)))
              LEFT JOIN widgets w ON ((w.block_id = b.id)))
            LEFT JOIN form_entries fe ON ((fe.widget_id = w.id)))
          LEFT JOIN donations d ON (((d.widget_id = w.id) AND (NOT d.subscription))))
        LEFT JOIN subscriptions s ON ((s.widget_id = w.id)))
      LEFT JOIN activist_pressures ap ON ((ap.widget_id = w.id)))
    JOIN activists a ON ((a.id = COALESCE(fe.activist_id, d.activist_id, s.activist_id, ap.activist_id))))
  GROUP BY c.id, m.id, w.id, a.id, fe.id, s.id, ap.id, d.id, fe.created_at, s.created_at, ap.created_at, d.created_at;


  --
  -- Name: form_entries generate_activists_from_generic_resource_with_widget; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER generate_activists_from_generic_resource_with_widget AFTER INSERT OR UPDATE ON public.form_entries FOR EACH ROW EXECUTE PROCEDURE generate_activists_from_generic_resource_with_widget();


  --
  -- Name: activist_pressures generate_activists_from_generic_resource_with_widget; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER generate_activists_from_generic_resource_with_widget AFTER INSERT OR UPDATE ON public.activist_pressures FOR EACH ROW EXECUTE PROCEDURE generate_activists_from_generic_resource_with_widget();


  --
  -- Name: donations generate_activists_from_generic_resource_with_widget; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER generate_activists_from_generic_resource_with_widget AFTER INSERT OR UPDATE ON public.donations FOR EACH ROW EXECUTE PROCEDURE generate_activists_from_generic_resource_with_widget();


  --
  -- Name: subscriptions generate_activists_from_generic_resource_with_widget; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER generate_activists_from_generic_resource_with_widget AFTER INSERT OR UPDATE ON public.subscriptions FOR EACH ROW EXECUTE PROCEDURE generate_activists_from_generic_resource_with_widget();


  --
  -- Name: mobilizations refresh_custom_domain_frontend; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER refresh_custom_domain_frontend AFTER INSERT OR UPDATE OF traefik_host_rule ON public.mobilizations FOR EACH ROW WHEN ((new.traefik_host_rule IS NOT NULL)) EXECUTE PROCEDURE refresh_custom_domain_frontend();


  --
  -- Name: activist_facebook_bot_interactions update_facebook_bot_activist_data; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER update_facebook_bot_activist_data AFTER INSERT OR UPDATE ON public.activist_facebook_bot_interactions FOR EACH ROW EXECUTE PROCEDURE update_facebook_bot_activists_full_text_index();


  --
  -- Name: twilio_configurations watched_create_twilio_configuration_trigger; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER watched_create_twilio_configuration_trigger AFTER INSERT OR UPDATE ON public.twilio_configurations FOR EACH ROW EXECUTE PROCEDURE notify_create_twilio_configuration_trigger();


  --
  -- Name: mobilizations watched_custom_domain; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER watched_custom_domain AFTER INSERT OR DELETE OR UPDATE ON public.mobilizations FOR EACH ROW EXECUTE PROCEDURE verify_custom_domain();


  --
  -- Name: twilio_calls watched_twilio_call_trigger; Type: TRIGGER; Schema: public; Owner: postgres
  --

  CREATE TRIGGER watched_twilio_call_trigger AFTER INSERT ON public.twilio_calls FOR EACH ROW EXECUTE PROCEDURE notify_twilio_call_trigger();


  --
  -- Name: notification_templates fk_rails_015164fe8d; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notification_templates
  ADD CONSTRAINT fk_rails_015164fe8d FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: mobilizations fk_rails_0786dde5c3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilizations
  ADD CONSTRAINT fk_rails_0786dde5c3 FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: subscriptions fk_rails_0ded3585f1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions
  ADD CONSTRAINT fk_rails_0ded3585f1 FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: facebook_bot_campaign_activists fk_rails_0ff272a657; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaign_activists
  ADD CONSTRAINT fk_rails_0ff272a657 FOREIGN KEY (facebook_bot_activist_id) REFERENCES facebook_bot_activists(id);


  --
  -- Name: activist_matches fk_rails_26ca62b2d0; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_matches
  ADD CONSTRAINT fk_rails_26ca62b2d0 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: notifications fk_rails_2fb35253bd; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications
  ADD CONSTRAINT fk_rails_2fb35253bd FOREIGN KEY (notification_template_id) REFERENCES notification_templates(id);


  --
  -- Name: recipients fk_rails_35bdfe7f89; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY recipients
  ADD CONSTRAINT fk_rails_35bdfe7f89 FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: subscriptions fk_rails_3bd353c401; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions
  ADD CONSTRAINT fk_rails_3bd353c401 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: activist_pressures fk_rails_3ff765ac30; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_pressures
  ADD CONSTRAINT fk_rails_3ff765ac30 FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: activist_tags fk_rails_4d2ba73b48; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_tags
  ADD CONSTRAINT fk_rails_4d2ba73b48 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: notifications fk_rails_4ea5195391; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications
  ADD CONSTRAINT fk_rails_4ea5195391 FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: matches fk_rails_5238d1bbc9; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY matches
  ADD CONSTRAINT fk_rails_5238d1bbc9 FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: subscriptions fk_rails_61f00b3de3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions
  ADD CONSTRAINT fk_rails_61f00b3de3 FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: addresses fk_rails_64d1e99667; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY addresses
  ADD CONSTRAINT fk_rails_64d1e99667 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: activist_pressures fk_rails_67eb37c69b; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_pressures
  ADD CONSTRAINT fk_rails_67eb37c69b FOREIGN KEY (cached_community_id) REFERENCES communities(id);


  --
  -- Name: facebook_bot_campaign_activists fk_rails_6ed0c7457d; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaign_activists
  ADD CONSTRAINT fk_rails_6ed0c7457d FOREIGN KEY (facebook_bot_campaign_id) REFERENCES facebook_bot_campaigns(id);


  --
  -- Name: donations fk_rails_7217bc1bdf; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT fk_rails_7217bc1bdf FOREIGN KEY (cached_community_id) REFERENCES communities(id);


  --
  -- Name: activist_matches fk_rails_7701a28e7f; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_matches
  ADD CONSTRAINT fk_rails_7701a28e7f FOREIGN KEY (match_id) REFERENCES matches(id);


  --
  -- Name: activist_pressures fk_rails_7e28014775; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_pressures
  ADD CONSTRAINT fk_rails_7e28014775 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: mobilization_activists fk_rails_821106ac31; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilization_activists
  ADD CONSTRAINT fk_rails_821106ac31 FOREIGN KEY (mobilization_id) REFERENCES mobilizations(id);


  --
  -- Name: activist_facebook_bot_interactions fk_rails_8229429c26; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_facebook_bot_interactions
  ADD CONSTRAINT fk_rails_8229429c26 FOREIGN KEY (facebook_bot_configuration_id) REFERENCES facebook_bot_configurations(id);


  --
  -- Name: twilio_calls fk_rails_8329ec7002; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY twilio_calls
  ADD CONSTRAINT fk_rails_8329ec7002 FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: notifications fk_rails_893eb4f32e; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications
  ADD CONSTRAINT fk_rails_893eb4f32e FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: form_entries fk_rails_920c5d67ae; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY form_entries
  ADD CONSTRAINT fk_rails_920c5d67ae FOREIGN KEY (cached_community_id) REFERENCES communities(id);


  --
  -- Name: donations fk_rails_9279978f7a; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT fk_rails_9279978f7a FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: donations fk_rails_98e396f4c1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT fk_rails_98e396f4c1 FOREIGN KEY (local_subscription_id) REFERENCES subscriptions(id);


  --
  -- Name: mobilization_activists fk_rails_9c54902f75; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY mobilization_activists
  ADD CONSTRAINT fk_rails_9c54902f75 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: community_activists fk_rails_a007365593; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_activists
  ADD CONSTRAINT fk_rails_a007365593 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: communities fk_rails_a268b06370; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY communities
  ADD CONSTRAINT fk_rails_a268b06370 FOREIGN KEY (recipient_id) REFERENCES recipients(id);


  --
  -- Name: donations fk_rails_aaa30ab12e; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT fk_rails_aaa30ab12e FOREIGN KEY (payable_transfer_id) REFERENCES payable_transfers(id);


  --
  -- Name: notifications fk_rails_b080fb4855; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY notifications
  ADD CONSTRAINT fk_rails_b080fb4855 FOREIGN KEY (user_id) REFERENCES users(id);


  --
  -- Name: activist_facebook_bot_interactions fk_rails_b2d73f1a99; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_facebook_bot_interactions
  ADD CONSTRAINT fk_rails_b2d73f1a99 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: facebook_bot_campaigns fk_rails_b518e26154; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY facebook_bot_campaigns
  ADD CONSTRAINT fk_rails_b518e26154 FOREIGN KEY (facebook_bot_configuration_id) REFERENCES facebook_bot_configurations(id);


  --
  -- Name: donations fk_rails_c1941efec9; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY donations
  ADD CONSTRAINT fk_rails_c1941efec9 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: dns_hosted_zones fk_rails_c6b1f8b17a; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_hosted_zones
  ADD CONSTRAINT fk_rails_c6b1f8b17a FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: invitations fk_rails_c70c9be1c0; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY invitations
  ADD CONSTRAINT fk_rails_c70c9be1c0 FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: form_entries fk_rails_cbe3790222; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY form_entries
  ADD CONSTRAINT fk_rails_cbe3790222 FOREIGN KEY (activist_id) REFERENCES activists(id);


  --
  -- Name: dns_records fk_rails_ce2c3e0b71; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY dns_records
  ADD CONSTRAINT fk_rails_ce2c3e0b71 FOREIGN KEY (dns_hosted_zone_id) REFERENCES dns_hosted_zones(id);


  --
  -- Name: balance_operations fk_rails_cee230e2a2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY balance_operations
  ADD CONSTRAINT fk_rails_cee230e2a2 FOREIGN KEY (recipient_id) REFERENCES recipients(id);


  --
  -- Name: form_entries fk_rails_db28a0ad48; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY form_entries
  ADD CONSTRAINT fk_rails_db28a0ad48 FOREIGN KEY (widget_id) REFERENCES widgets(id);


  --
  -- Name: activist_tags fk_rails_e8fa6ecb6c; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY activist_tags
  ADD CONSTRAINT fk_rails_e8fa6ecb6c FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: user_tags fk_rails_ea0382482a; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY user_tags
  ADD CONSTRAINT fk_rails_ea0382482a FOREIGN KEY (user_id) REFERENCES users(id);


  --
  -- Name: community_activists fk_rails_fa4f63f07b; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY community_activists
  ADD CONSTRAINT fk_rails_fa4f63f07b FOREIGN KEY (community_id) REFERENCES communities(id);


  --
  -- Name: subscriptions gateway_subscription_fk; Type: FK CONSTRAINT; Schema: public; Owner: postgres
  --

  ALTER TABLE ONLY subscriptions
  ADD CONSTRAINT gateway_subscription_fk FOREIGN KEY (gateway_subscription_id) REFERENCES gateway_subscriptions(id);


  --
  -- Name: postgraphile_watch_ddl; Type: EVENT TRIGGER; Schema: -; Owner: postgres
  --

  CREATE EVENT TRIGGER postgraphile_watch_ddl ON ddl_command_end
  WHEN TAG IN ('ALTER DOMAIN', 'ALTER FOREIGN TABLE', 'ALTER FUNCTION', 'ALTER SCHEMA', 'ALTER TABLE', 'ALTER TYPE', 'ALTER VIEW', 'COMMENT', 'CREATE DOMAIN', 'CREATE FOREIGN TABLE', 'CREATE FUNCTION', 'CREATE SCHEMA', 'CREATE TABLE', 'CREATE TABLE AS', 'CREATE VIEW', 'DROP DOMAIN', 'DROP FOREIGN TABLE', 'DROP FUNCTION', 'DROP SCHEMA', 'DROP TABLE', 'DROP VIEW', 'GRANT', 'REVOKE', 'SELECT INTO')
    EXECUTE PROCEDURE postgraphile_watch.notify_watchers_ddl();


    ALTER EVENT TRIGGER postgraphile_watch_ddl OWNER TO postgres;

    --
    -- Name: postgraphile_watch_drop; Type: EVENT TRIGGER; Schema: -; Owner: postgres
    --

    CREATE EVENT TRIGGER postgraphile_watch_drop ON sql_drop
    EXECUTE PROCEDURE postgraphile_watch.notify_watchers_drop();


    ALTER EVENT TRIGGER postgraphile_watch_drop OWNER TO postgres;

    --
    -- Name: microservices; Type: ACL; Schema: -; Owner: postgres
    --

    GRANT USAGE ON SCHEMA microservices TO microservices;


    --
    -- Name: pgjwt; Type: ACL; Schema: -; Owner: postgres
    --

    GRANT USAGE ON SCHEMA pgjwt TO microservices;
    GRANT USAGE ON SCHEMA pgjwt TO postgraphql;
    GRANT USAGE ON SCHEMA pgjwt TO anonymous;


    --
    -- Name: postgraphql; Type: ACL; Schema: -; Owner: postgres
    --

    GRANT USAGE ON SCHEMA postgraphql TO anonymous;
    GRANT USAGE ON SCHEMA postgraphql TO common_user;
    GRANT USAGE ON SCHEMA postgraphql TO admin;


    --
    -- Name: public; Type: ACL; Schema: -; Owner: postgres
    --

    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO admin;
    GRANT USAGE ON SCHEMA public TO postgraphql;
    GRANT USAGE ON SCHEMA public TO common_user;
    GRANT USAGE ON SCHEMA public TO anonymous;
    GRANT USAGE ON SCHEMA public TO microservices;


    SET search_path = microservices, pg_catalog;

    --
    -- Name: create_community_dns(json); Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT ALL ON FUNCTION create_community_dns(data json) TO microservices;
    GRANT ALL ON FUNCTION create_community_dns(data json) TO postgraphql;


    SET search_path = public, pg_catalog;

    --
    -- Name: users; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,UPDATE ON TABLE users TO common_user;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE users TO admin;
    GRANT SELECT ON TABLE users TO microservices;
    GRANT SELECT,INSERT,UPDATE ON TABLE users TO anonymous;


    --
    -- Name: twilio_calls; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO common_user;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO anonymous;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: twilio_calls; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO common_user;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_calls TO anonymous;


    --
    -- Name: twilio_configurations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_configurations TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_configurations TO common_user;


    --
    -- Name: change_password(json); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION change_password(data json) TO common_user;
    GRANT ALL ON FUNCTION change_password(data json) TO admin;
    GRANT ALL ON FUNCTION change_password(data json) TO anonymous;


    SET search_path = public, pg_catalog;

    --
    -- Name: invitations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE invitations TO anonymous;
    GRANT SELECT ON TABLE invitations TO common_user;
    GRANT SELECT ON TABLE invitations TO admin;
    GRANT SELECT ON TABLE invitations TO postgraphql;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: create_community(json); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION create_community(data json) TO common_user;
    GRANT ALL ON FUNCTION create_community(data json) TO admin;
    GRANT ALL ON FUNCTION create_community(data json) TO anonymous;


    --
    -- Name: create_dns_record(json); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION create_dns_record(data json) TO postgraphql;


    SET search_path = public, pg_catalog;

    --
    -- Name: facebook_bot_campaigns; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_campaigns TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_campaigns TO common_user;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: create_tags(text, text); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION create_tags(name text, label text) TO common_user;
    GRANT ALL ON FUNCTION create_tags(name text, label text) TO admin;
    GRANT ALL ON FUNCTION create_tags(name text, label text) TO postgraphql;


    --
    -- Name: create_user_tags(json); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION create_user_tags(data json) TO common_user;
    GRANT ALL ON FUNCTION create_user_tags(data json) TO admin;
    GRANT ALL ON FUNCTION create_user_tags(data json) TO postgraphql;


    --
    -- Name: users; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE users TO common_user;


    SET search_path = public, pg_catalog;

    --
    -- Name: template_mobilizations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE template_mobilizations TO common_user;


    --
    -- Name: activist_tags; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE activist_tags TO common_user;
    GRANT SELECT,INSERT ON TABLE activist_tags TO admin;


    --
    -- Name: taggings; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE taggings TO common_user;
    GRANT SELECT,INSERT ON TABLE taggings TO admin;


    --
    -- Name: tags; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,UPDATE ON TABLE tags TO common_user;
    GRANT SELECT,INSERT,UPDATE ON TABLE tags TO admin;
    GRANT SELECT,INSERT,UPDATE ON TABLE tags TO postgraphql;


    --
    -- Name: community_tags; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE community_tags TO common_user;
    GRANT SELECT ON TABLE community_tags TO admin;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: community_tags; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE community_tags TO common_user;
    GRANT SELECT ON TABLE community_tags TO admin;


    --
    -- Name: get_widget_donation_stats(integer); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION get_widget_donation_stats(widget_id integer) TO anonymous;


    --
    -- Name: mobilizations(integer); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION mobilizations(days integer) TO common_user;
    GRANT ALL ON FUNCTION mobilizations(days integer) TO admin;
    GRANT ALL ON FUNCTION mobilizations(days integer) TO postgraphql;


    SET search_path = public, pg_catalog;

    --
    -- Name: communities; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE communities TO common_user;
    GRANT SELECT,INSERT ON TABLE communities TO admin;
    GRANT SELECT ON TABLE communities TO microservices;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: communities; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE communities TO common_user;
    GRANT SELECT ON TABLE communities TO admin;
    GRANT SELECT ON TABLE communities TO postgraphql;


    SET search_path = public, pg_catalog;

    --
    -- Name: mobilizations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE mobilizations TO common_user;
    GRANT SELECT ON TABLE mobilizations TO admin;
    GRANT SELECT ON TABLE mobilizations TO postgraphql;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: mobilizations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE mobilizations TO common_user;
    GRANT SELECT ON TABLE mobilizations TO admin;
    GRANT SELECT ON TABLE mobilizations TO postgraphql;


    --
    -- Name: reset_password_change_password(text, text); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION reset_password_change_password(new_password text, token text) TO anonymous;


    --
    -- Name: reset_password_token_verify(text); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION reset_password_token_verify(token text) TO anonymous;


    SET search_path = public, pg_catalog;

    --
    -- Name: activists; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE activists TO admin;
    GRANT SELECT,INSERT ON TABLE activists TO common_user;


    --
    -- Name: community_activists; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE community_activists TO common_user;
    GRANT SELECT,INSERT ON TABLE community_activists TO admin;


    --
    -- Name: community_users; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE community_users TO common_user;
    GRANT SELECT,INSERT ON TABLE community_users TO admin;
    GRANT SELECT,INSERT ON TABLE community_users TO anonymous;
    GRANT SELECT,INSERT ON TABLE community_users TO postgraphql;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: activists; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE activists TO common_user;
    GRANT SELECT ON TABLE activists TO admin;


    --
    -- Name: total_sum_transfer_operations_from_community(integer); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION total_sum_transfer_operations_from_community(community_id integer) TO common_user;
    GRANT ALL ON FUNCTION total_sum_transfer_operations_from_community(community_id integer) TO admin;


    SET search_path = public, pg_catalog;

    --
    -- Name: facebook_bot_campaign_activists; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_campaign_activists TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_campaign_activists TO common_user;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: user_mobilizations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE user_mobilizations TO common_user;
    GRANT SELECT ON TABLE user_mobilizations TO admin;


    --
    -- Name: user_mobilizations_community(user_mobilizations); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION user_mobilizations_community(m user_mobilizations) TO common_user;
    GRANT ALL ON FUNCTION user_mobilizations_community(m user_mobilizations) TO admin;


    --
    -- Name: user_mobilizations_score(user_mobilizations); Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT ALL ON FUNCTION user_mobilizations_score(m user_mobilizations) TO common_user;
    GRANT ALL ON FUNCTION user_mobilizations_score(m user_mobilizations) TO admin;


    SET search_path = public, pg_catalog;

    --
    -- Name: configuration(text); Type: ACL; Schema: public; Owner: postgres
    --

    GRANT ALL ON FUNCTION configuration(name text) TO microservices;
    GRANT ALL ON FUNCTION configuration(name text) TO postgraphql;
    GRANT ALL ON FUNCTION configuration(name text) TO anonymous;


    --
    -- Name: form_entries; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE form_entries TO common_user;
    GRANT SELECT ON TABLE form_entries TO admin;


    --
    -- Name: activist_pressures; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE activist_pressures TO common_user;
    GRANT SELECT ON TABLE activist_pressures TO admin;


    --
    -- Name: subscriptions; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE subscriptions TO common_user;
    GRANT SELECT ON TABLE subscriptions TO admin;


    --
    -- Name: donations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE donations TO common_user;
    GRANT SELECT ON TABLE donations TO admin;
    GRANT SELECT ON TABLE donations TO anonymous;


    --
    -- Name: verify_custom_domain(); Type: ACL; Schema: public; Owner: postgres
    --

    GRANT ALL ON FUNCTION verify_custom_domain() TO postgraphql;
    GRANT ALL ON FUNCTION verify_custom_domain() TO admin;
    GRANT ALL ON FUNCTION verify_custom_domain() TO microservices;


    SET search_path = microservices, pg_catalog;

    --
    -- Name: certificates; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE certificates TO microservices;


    --
    -- Name: communities; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE communities TO microservices;


    SET search_path = public, pg_catalog;

    --
    -- Name: dns_hosted_zones; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE dns_hosted_zones TO microservices;


    SET search_path = microservices, pg_catalog;

    --
    -- Name: dns_hosted_zones; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE dns_hosted_zones TO microservices;


    --
    -- Name: mobilizations; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE mobilizations TO microservices;


    SET search_path = public, pg_catalog;

    --
    -- Name: notification_templates; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE notification_templates TO anonymous;
    GRANT SELECT ON TABLE notification_templates TO common_user;
    GRANT SELECT ON TABLE notification_templates TO admin;
    GRANT SELECT ON TABLE notification_templates TO microservices;


    SET search_path = microservices, pg_catalog;

    --
    -- Name: notification_templates; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE notification_templates TO microservices;


    SET search_path = public, pg_catalog;

    --
    -- Name: notifications; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE notifications TO anonymous;
    GRANT SELECT,INSERT ON TABLE notifications TO common_user;
    GRANT SELECT,INSERT ON TABLE notifications TO admin;
    GRANT SELECT ON TABLE notifications TO microservices;


    SET search_path = microservices, pg_catalog;

    --
    -- Name: notifications; Type: ACL; Schema: microservices; Owner: postgres
    --

    GRANT SELECT ON TABLE notifications TO microservices;


    SET search_path = public, pg_catalog;

    --
    -- Name: activist_facebook_bot_interactions; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE activist_facebook_bot_interactions TO admin;


    --
    -- Name: facebook_bot_configurations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_configurations TO admin;


    --
    -- Name: mobilization_activists; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE mobilization_activists TO common_user;
    GRANT SELECT ON TABLE mobilization_activists TO admin;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: activist_mobilizations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE activist_mobilizations TO common_user;
    GRANT SELECT ON TABLE activist_mobilizations TO admin;


    --
    -- Name: activist_tags; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE activist_tags TO admin;
    GRANT SELECT ON TABLE activist_tags TO common_user;


    SET search_path = public, pg_catalog;

    --
    -- Name: balance_operations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE balance_operations TO common_user;
    GRANT SELECT ON TABLE balance_operations TO admin;


    --
    -- Name: balance_operation_summaries; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE balance_operation_summaries TO common_user;
    GRANT SELECT ON TABLE balance_operation_summaries TO admin;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: balance_operations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE balance_operations TO common_user;
    GRANT SELECT ON TABLE balance_operations TO admin;


    --
    -- Name: facebook_activist_interactions; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE facebook_activist_interactions TO admin;
    GRANT SELECT ON TABLE facebook_activist_interactions TO common_user;
    GRANT SELECT ON TABLE facebook_activist_interactions TO anonymous;


    --
    -- Name: bot_recipients; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE bot_recipients TO admin;


    --
    -- Name: community_user_roles; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE community_user_roles TO common_user;
    GRANT SELECT ON TABLE community_user_roles TO admin;


    SET search_path = public, pg_catalog;

    --
    -- Name: blocks; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE blocks TO common_user;
    GRANT SELECT ON TABLE blocks TO admin;


    --
    -- Name: widgets; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE widgets TO common_user;
    GRANT SELECT ON TABLE widgets TO admin;
    GRANT SELECT ON TABLE widgets TO anonymous;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: donations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE donations TO common_user;
    GRANT SELECT ON TABLE donations TO admin;


    --
    -- Name: facebook_bot_configurations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE facebook_bot_configurations TO admin;


    --
    -- Name: facebook_bot_interactions; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE facebook_bot_interactions TO admin;
    GRANT SELECT ON TABLE facebook_bot_interactions TO common_user;
    GRANT SELECT ON TABLE facebook_bot_interactions TO anonymous;


    SET search_path = public, pg_catalog;

    --
    -- Name: activist_participations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE activist_participations TO common_user;
    GRANT SELECT ON TABLE activist_participations TO admin;


    SET search_path = postgraphql, pg_catalog;

    --
    -- Name: participations; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE participations TO common_user;
    GRANT SELECT ON TABLE participations TO admin;


    --
    -- Name: tags; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE tags TO postgraphql;
    GRANT SELECT ON TABLE tags TO common_user;
    GRANT SELECT ON TABLE tags TO admin;


    --
    -- Name: user_communities; Type: ACL; Schema: postgraphql; Owner: postgres
    --

    GRANT SELECT ON TABLE user_communities TO common_user;
    GRANT SELECT ON TABLE user_communities TO admin;


    SET search_path = public, pg_catalog;

    --
    -- Name: activist_actions; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE activist_actions TO common_user;
    GRANT SELECT ON TABLE activist_actions TO admin;
    GRANT SELECT ON TABLE activist_actions TO postgraphql;


    --
    -- Name: activist_facebook_bot_interactions_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE activist_facebook_bot_interactions_id_seq TO admin;


    --
    -- Name: activist_tags_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE activist_tags_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE activist_tags_id_seq TO admin;


    --
    -- Name: activists_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE activists_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE activists_id_seq TO postgraphql;
    GRANT USAGE ON SEQUENCE activists_id_seq TO admin;


    --
    -- Name: communities_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE communities_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE communities_id_seq TO admin;


    --
    -- Name: community_activists_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE community_activists_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE community_activists_id_seq TO admin;


    --
    -- Name: community_users_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE community_users_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE community_users_id_seq TO admin;
    GRANT USAGE ON SEQUENCE community_users_id_seq TO anonymous;
    GRANT USAGE ON SEQUENCE community_users_id_seq TO postgraphql;


    --
    -- Name: configurations; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT ON TABLE configurations TO microservices;
    GRANT SELECT ON TABLE configurations TO postgraphql;
    GRANT SELECT ON TABLE configurations TO anonymous;


    --
    -- Name: dns_hosted_zones_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE dns_hosted_zones_id_seq TO microservices;


    --
    -- Name: dns_records; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT ON TABLE dns_records TO admin;
    GRANT SELECT,INSERT ON TABLE dns_records TO microservices;
    GRANT SELECT,INSERT ON TABLE dns_records TO postgraphql;


    --
    -- Name: dns_records_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE dns_records_id_seq TO postgraphql;
    GRANT USAGE ON SEQUENCE dns_records_id_seq TO microservices;
    GRANT USAGE ON SEQUENCE dns_records_id_seq TO admin;


    --
    -- Name: facebook_bot_activists; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_activists TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_activists TO common_user;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE facebook_bot_activists TO anonymous;


    --
    -- Name: facebook_bot_activists_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE facebook_bot_activists_id_seq TO admin;
    GRANT USAGE ON SEQUENCE facebook_bot_activists_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE facebook_bot_activists_id_seq TO anonymous;


    --
    -- Name: facebook_bot_campaign_activists_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE facebook_bot_campaign_activists_id_seq TO admin;
    GRANT USAGE ON SEQUENCE facebook_bot_campaign_activists_id_seq TO common_user;


    --
    -- Name: facebook_bot_campaigns_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE facebook_bot_campaigns_id_seq TO admin;
    GRANT USAGE ON SEQUENCE facebook_bot_campaigns_id_seq TO common_user;


    --
    -- Name: facebook_bot_configurations_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE facebook_bot_configurations_id_seq TO admin;


    --
    -- Name: notifications_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE notifications_id_seq TO anonymous;
    GRANT USAGE ON SEQUENCE notifications_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE notifications_id_seq TO admin;


    --
    -- Name: taggings_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE taggings_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE taggings_id_seq TO admin;


    --
    -- Name: tags_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE tags_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE tags_id_seq TO admin;


    --
    -- Name: twilio_call_transitions; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_call_transitions TO admin;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_call_transitions TO common_user;
    GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE twilio_call_transitions TO anonymous;


    --
    -- Name: twilio_calls_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE twilio_calls_id_seq TO admin;
    GRANT USAGE ON SEQUENCE twilio_calls_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE twilio_calls_id_seq TO anonymous;


    --
    -- Name: twilio_configurations_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE twilio_configurations_id_seq TO admin;
    GRANT USAGE ON SEQUENCE twilio_configurations_id_seq TO common_user;


    --
    -- Name: user_tags; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT SELECT,INSERT,UPDATE ON TABLE user_tags TO common_user;
    GRANT SELECT,INSERT,UPDATE ON TABLE user_tags TO admin;
    GRANT SELECT,INSERT,UPDATE ON TABLE user_tags TO postgraphql;


    --
    -- Name: user_tags_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE user_tags_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE user_tags_id_seq TO admin;


    --
    -- Name: users_id_seq; Type: ACL; Schema: public; Owner: postgres
    --

    GRANT USAGE ON SEQUENCE users_id_seq TO anonymous;
    GRANT USAGE ON SEQUENCE users_id_seq TO common_user;
    GRANT USAGE ON SEQUENCE users_id_seq TO admin;


    --
    -- PostgreSQL database dump complete
    --
