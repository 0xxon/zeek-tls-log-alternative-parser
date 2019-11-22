TLS Log Parser
==============

This is a database parser for the alternative TLS log files that are created by the scripts
located at https://github.com/0xxon/perl-zeek-log-parse.

Note
----

Please note that it is likely that this code is not very useful to you. This part of the code that drives some of the statistics of the ICSI SSL Notary. The database that is created by these scripts only retains extremely high level statistics - which is necessary due to the size of the ICSI dataset.

Since this code evolved over many research projects it is sadly underdocumented and messy.

Privacy Note
------------

Note that you should think about user privacy when deploying a setup like this in larger networks. The ICSI Notary does not store client IP address information. Note that this anonymization is _not_ present in the scripts at https://github.com/0xxon/perl-zeek-log-parse.

Requirements
------------

To run this script, you first must install the required modules. The easy to do this is to execute the file ```install-prereqs.sh```.

If that is not possible, you also can install these modules manually:

```
DBD::Pg
MooseX::Runnable
Rose::DB::Object
Pg::hstore
Number::Format
Digest::SHA1
JSON
JSON::XS
Zeek::Log::Parse
YAML
YAML::XS
Perl6::Slurp
Date::Parse
Carp::Assert
Module::Install
Math::BigInt::GMP
```

Running
-------

After installing the requirements, you need to set up a postgresql database. By default it is assumed that the database is listening on port 7779, the database name is ```tls``` and that the local user has full access to the database.

The necessary table can be created by starting the program ```CertReader::App::CreatetablesPostgres``` using ```mx-run```.

Afterwards, data can be read into the table by using ```CertReader::App::Readseen```.

Please see the script ```createTestEnvironment.sh``` - this script creates a new postgres database, creates the table and imports two test files.

Note that parsing of larger log-files can take a quite large amount of time. It is possible to have an arbitrary number of ReadSeen instances running simultaneously - they do not interfere with each other.

Results
-------

This project loads the resulting information in one table called ```seen_stats```. The column names should be rather self explanatory. Note that this relies quite heavily on the postgresql hstore datatype - see https://www.postgresql.org/docs/12/hstore.html for details on how to query it. The ```tls_signature``` fields are a concatenation of a number of different fields to make counting easier - please see ```Readseen.pm``` for how exactly they are put together.