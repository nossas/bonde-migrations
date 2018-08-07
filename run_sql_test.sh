#! /bin/bash
diesel setup --database-url="postgres://postgres:3x4mpl3@db.devel:5432/bonde_test"
diesel migration --database-url="postgres://postgres:3x4mpl3@db.devel:5432/bonde_test" run
docker run -t --net host --rm -v $(pwd)/specs:/specs nossas/docker-pgtap:develop -h db.devel -u postgres -w 3x4mpl3 -d bonde_test -t '/specs/**/**/*.sql'
