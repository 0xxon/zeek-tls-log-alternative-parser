package CertReader::ORM;

use 5.10.1;
use strict;
use warnings;

use Carp;

use Moose::Role;

use CertReader::DB;
use CertReader::DB::SeenStats;

has '_db' => (
	is => 'rw',
	required => 0,
	accessor => 'db',
	lazy => 1,
	builder => '__initdb',
);

has 'domain' => (
	is => 'rw',
	isa => 'Str',
	required => 0,
	documentation => "Current database domain",
);

sub __initdb {
	my $self = shift;

	$self->set_tablenames();
	if ( defined($self->domain) ) {
		CertReader::DB->default_domain($self->domain);
	}

	my $db = CertReader::DB->new;

	$db->dbh->{pg_enable_utf8}=1; # boy, this is important...

	return $db;
}

sub set_tablenames {
	shift;


	CertReader::DB::SeenStats->meta->table("seen_stats");
}

1;
