-- FUNCTION: postgraphql.get_widget_donation_stats(integer)

-- DROP FUNCTION postgraphql.get_widget_donation_stats(integer);

CREATE OR REPLACE FUNCTION postgraphql.get_widget_donation_stats(
	widget_id integer)
    RETURNS json
    LANGUAGE 'sql'

    COST 100
    STABLE 
AS $BODY$
        select
            json_build_object(
            'pledged', sum(d.amount / 100) + coalesce(nullif(w.settings::json->>'external_resource', ''), '0')::bigint,
            'widget_id', w.id,
            'goal', w.goal,
            'progress', ((sum(d.amount / 100) + coalesce(nullif(w.settings::json->>'external_resource', ''), '0')::bigint) / w.goal) * 100,
            'total_donations', (count(distinct d.id)),
            'total_donators', (count(distinct d.activist_id))
            )
        from widgets w
            join donations d on d.widget_id = w.id
            where w.id = $1 and
                d.transaction_status = 'paid'
            group by w.id;
        $BODY$;

ALTER FUNCTION postgraphql.get_widget_donation_stats(integer)
    OWNER TO reboo;

GRANT EXECUTE ON FUNCTION postgraphql.get_widget_donation_stats(integer) TO anonymous;

GRANT EXECUTE ON FUNCTION postgraphql.get_widget_donation_stats(integer) TO PUBLIC;

GRANT EXECUTE ON FUNCTION postgraphql.get_widget_donation_stats(integer) TO reboo;

COMMENT ON FUNCTION postgraphql.get_widget_donation_stats(integer)
    IS 'Returns a json with pledged, progress and goal from widget';
