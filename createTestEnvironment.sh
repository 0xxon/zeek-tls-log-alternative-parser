#!/usr/bin/env bash

initdb postgres
perl -pi.bak -E "s/#port =.*/port = 7779/;" postgres/postgresql.conf
pg_ctl start -D postgres -l serverlog
sleep 2
createdb -p 7779 tls
mx-run -Ilib CertReader::App::CreatetablesPostgres

# Ok, from here it is test-code. So, instead of loading this, load your own data.
# readseen is parallelizable - they just dump data to the DB.
# They might show errors when they encounter conflicts, but they re-try. If they can
# not continue for some reason, they will exit with an abnormal error code, not
# just complain.
#
# Usual ways to run are something along the lines of:
#
# find ./ -name “tls*.log.gz” -print0 | xargs -0 -P32 -n5 mx-run -Ilib CertReader::App::Readseen

mx-run -Ilib CertReader::App::Readseen testdata/tls_1_3.log
mx-run -Ilib CertReader::App::Readseen testdata/tls-2009-M57-day11-18.log

