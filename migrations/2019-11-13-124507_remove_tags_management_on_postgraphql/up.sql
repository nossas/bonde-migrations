-- drop function to create relationship between user and tag
DROP FUNCTION IF EXISTS postgraphql.create_user_tags();
-- drop function to create tag
DROP FUNCTION IF EXISTS postgraphql.create_tags();
-- drop view that queryng
DROP VIEW IF EXISTS postgraphql.tags;