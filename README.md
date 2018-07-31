## under development

> TODO

- [ ] create dockerfile
- [ ] create config for deploy
- [x] create initial schema from database
- [ ] run sql specs in this repo

### bonde-migrations


## database roles

```
create role postgraphql login password '3x4mpl3';
create role anonymous;
create role common_user;
create role admin;
```

## create a new migration

`diesel migration generate migration_name`


## running migrations

`diesel migration run`


## rollback your migration

`diesel migration redo`
