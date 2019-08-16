-- This file should undo anything in `up.sql`

DROP SCHEMA microservices;
DROP SCHEMA pgjwt;
DROP SCHEMA postgraphile_watch;
DROP SCHEMA postgraphql;
drop role postgraphql;
drop role anonymous;
drop role common_user;
drop role admin;
drop role postgres;
drop role microservices;

