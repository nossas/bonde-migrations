-- View: postgraphql.mobilizations

-- DROP VIEW postgraphql.mobilizations;

CREATE OR REPLACE VIEW postgraphql.mobilizations
 AS
 SELECT m.id,
    m.name,
    m.created_at,
    m.updated_at,
    m.user_id,
    m.color_scheme,
    m.google_analytics_code,
    m.goal,
    m.facebook_share_title,
    m.facebook_share_description,
    m.header_font,
    m.body_font,
    m.facebook_share_image,
    m.slug,
    m.custom_domain,
    m.twitter_share_text,
    m.community_id,
    m.favicon,
    m.deleted_at,
    m.status
   FROM mobilizations m
  WHERE m.deleted_at IS NULL;

ALTER TABLE postgraphql.mobilizations
    OWNER TO monkey_user;

GRANT SELECT ON TABLE postgraphql.mobilizations TO admin;
GRANT SELECT ON TABLE postgraphql.mobilizations TO common_user;
GRANT ALL ON TABLE postgraphql.mobilizations TO monkey_user;
GRANT SELECT ON TABLE postgraphql.mobilizations TO postgraphql;

-- View: postgraphql.user_mobilizations

-- DROP VIEW postgraphql.user_mobilizations;

CREATE OR REPLACE VIEW postgraphql.user_mobilizations
 AS
 SELECT m.id,
    m.name,
    m.created_at,
    m.updated_at,
    m.user_id,
    m.color_scheme,
    m.google_analytics_code,
    m.goal,
    m.facebook_share_title,
    m.facebook_share_description,
    m.header_font,
    m.body_font,
    m.facebook_share_image,
    m.slug,
    m.custom_domain,
    m.twitter_share_text,
    m.community_id,
    m.favicon,
    m.deleted_at,
    m.status
   FROM postgraphql.mobilizations m
     JOIN community_users cou ON cou.community_id = m.community_id
  WHERE cou.user_id = postgraphql.current_user_id();

ALTER TABLE postgraphql.user_mobilizations
    OWNER TO monkey_user;

GRANT SELECT ON TABLE postgraphql.user_mobilizations TO admin;
GRANT SELECT ON TABLE postgraphql.user_mobilizations TO common_user;
GRANT ALL ON TABLE postgraphql.user_mobilizations TO monkey_user;

-- FUNCTION: postgraphql.user_mobilizations_community(postgraphql.user_mobilizations)

-- DROP FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations);

CREATE OR REPLACE FUNCTION postgraphql.user_mobilizations_community(
    m postgraphql.user_mobilizations)
    RETURNS postgraphql.communities
    LANGUAGE 'sql'

    COST 100
    STABLE 
AS $BODY$
    select c.*
    from postgraphql.communities c
    where c.id = m.community_id
$BODY$;

ALTER FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations)
    OWNER TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations) TO admin;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations) TO common_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations) TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations) TO PUBLIC;

-- FUNCTION: postgraphql.user_mobilizations_score(postgraphql.user_mobilizations)

-- DROP FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations);

CREATE OR REPLACE FUNCTION postgraphql.user_mobilizations_score(
    m postgraphql.user_mobilizations)
    RETURNS integer
    LANGUAGE 'sql'

    COST 100
    STABLE 
AS $BODY$
    select count(1)::INT
    from public.activist_actions aa
        where aa.mobilization_id  = m.id
$BODY$;

ALTER FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations)
    OWNER TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations) TO admin;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations) TO common_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations) TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations) TO PUBLIC;

-- FUNCTION: postgraphql.trending_mobilizations(integer)

-- DROP FUNCTION postgraphql.trending_mobilizations(integer);

CREATE OR REPLACE FUNCTION postgraphql.trending_mobilizations(
    days integer)
    RETURNS SETOF postgraphql.mobilizations 
    LANGUAGE 'sql'

    COST 100
    STABLE 
    ROWS 1000
AS $BODY$
select m.*
from postgraphql.mobilizations m
left join lateral (
    select count(1)
    from public.activist_actions aa
        where aa.mobilization_id  = m.id
            and aa.action_created_date >= now()::date - (days || ' days')::interval
) as score on true
order by score desc;
$BODY$;

ALTER FUNCTION postgraphql.trending_mobilizations(integer)
    OWNER TO monkey_user;

-- FUNCTION: postgraphql.mobilizations_community(postgraphql.mobilizations)

-- DROP FUNCTION postgraphql.mobilizations_community(postgraphql.mobilizations);

CREATE OR REPLACE FUNCTION postgraphql.mobilizations_community(
    m postgraphql.mobilizations)
    RETURNS postgraphql.communities
    LANGUAGE 'sql'

    COST 100
    STABLE 
AS $BODY$
    select c.*
    from postgraphql.communities c
    where c.id = m.community_id
$BODY$;

ALTER FUNCTION postgraphql.mobilizations_community(postgraphql.mobilizations)
    OWNER TO monkey_user;

-- FUNCTION: postgraphql.mobilizations(integer)

-- DROP FUNCTION postgraphql.mobilizations(integer);

CREATE OR REPLACE FUNCTION postgraphql.mobilizations(
    days integer)
    RETURNS json
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
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
$BODY$;

ALTER FUNCTION postgraphql.mobilizations(integer)
    OWNER TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.mobilizations(integer) TO admin;

GRANT EXECUTE ON FUNCTION postgraphql.mobilizations(integer) TO common_user;

GRANT EXECUTE ON FUNCTION postgraphql.mobilizations(integer) TO monkey_user;

GRANT EXECUTE ON FUNCTION postgraphql.mobilizations(integer) TO PUBLIC;

GRANT EXECUTE ON FUNCTION postgraphql.mobilizations(integer) TO postgraphql;

