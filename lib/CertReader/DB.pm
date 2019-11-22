package CertReader::DB;

use 5.10.1;
use strict;
use warnings;

use Rose::DB;
our @ISA = qw(Rose::DB);

# Use a private registry for this class
__PACKAGE__->use_private_registry;

my $default_port = 7779;
if ( $ENV{POSTGRES_DB_PORT} ) {
	$default_port = $ENV{POSTGRES_DB_PORT};
}

__PACKAGE__->register_db(
	domain => CertReader::DB->default_domain,
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'tls',
	port => $default_port,
);

1;
