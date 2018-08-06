## under development

> TODO

- [x] create dockerfile
- [ ] create config for deploy
- [x] create initial schema from database
- [ ] run sql specs in this repo
- [ ] create makefile to simplify to run migrations and specs

### bonde-migrations

## database roles

```
create role postgraphql login password '3x4mpl3';
create role anonymous;
create role common_user;
create role admin;
```

## create a new migration

`diesel migration --database-url="postgres://postgres@localhost:5432/db" generate migration_name`


## running migrations

`diesel migration --database-url="postgres://postgres@localhost:5432/db "run`


## rollback your migration

`diesel migration --database-url="postgres://postgres@localhost:5432/db" redo`


## how to run with docker

`docker run --net=host -e DATABASE_URL="postgres://postgres@localhost:5432/db" -it nossas/bonde-migrations diesel migration run`

## run specs
`docker run -t --net host --rm -v $(pwd)/specs:/specs nossas/docker-pgtap:develop -h localhost -u postgres -w password -d db_test -t '/specs/**/**/*.sql'`
