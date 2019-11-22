#!/usr/bin/env bash
#
# Install all needed prerequisites from a "clean" perl installation

cpan install DBD::Pg
cpan install MooseX::Runnable
cpan install Rose::DB::Object
cpan install Pg::hstore
cpan install Number::Format
cpan install Digest::SHA1
cpan install JSON
cpan install JSON::XS
cpan install Zeek::Log::Parse
cpan install YAML
cpan install YAML::XS
cpan install Perl6::Slurp
cpan install Date::Parse 
cpan install Carp::Assert
cpan install Module::Install
cpan install Math::BigInt::GMP
