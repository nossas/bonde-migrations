/*ERROR: cannot drop view postgraphql.mobilizations because other objects depend on it DETAIL: view postgraphql.user_mobilizations depends on view postgraphql.mobilizations function postgraphql.user_mobilizations_community(postgraphql.user_mobilizations) depends on type postgraphql.user_mobilizations function postgraphql.user_mobilizations_score(postgraphql.user_mobilizations) depends on type postgraphql.user_mobilizations function postgraphql.mobilizations_community(postgraphql.mobilizations) depends on type postgraphql.mobilizations function postgraphql.trending_mobilizations(integer) depends on type postgraphql.mobilizations HINT: Use DROP ... CASCADE to drop the dependent objects too. */

-- Function: postgraphql.user_mobilizations_community
DROP FUNCTION postgraphql.user_mobilizations_community(postgraphql.user_mobilizations);

-- Function: postgraphql.user_mobilizations_score(postgraphql.user_mobilizations)

DROP FUNCTION postgraphql.user_mobilizations_score(postgraphql.user_mobilizations);

-- View: postgraphql.user_mobilizations
DROP VIEW postgraphql.user_mobilizations;

-- Function: postgraphql.trending_mobilizations(integer)
DROP FUNCTION postgraphql.trending_mobilizations(integer);

-- Function: postgraphql.mobilizations_community(postgraphql.mobilizations)
DROP FUNCTION postgraphql.mobilizations_community(postgraphql.mobilizations);

-- View: postgraphql.mobilizations
DROP VIEW postgraphql.mobilizations;

-- Function: postgraphql.mobilizations(integer)
DROP FUNCTION postgraphql.mobilizations(integer);

drop view postgraphql.user_communities;