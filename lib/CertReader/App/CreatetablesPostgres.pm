package CertReader::App::CreatetablesPostgres;

# application to create our required tables for postgres

use 5.14.1;
use strict;
use warnings;

use Moose;
with 'MooseX::Getopt';
with 'MooseX::Runnable';
with 'CertReader::ORM';

sub run {
	my $self = shift;

	my @commands;

	# fail early
	push(@commands, "CREATE EXTENSION IF NOT EXISTS hstore;");

	push (@commands, <<END);
CREATE TABLE seen_stats (
	id serial unique not null,
	file_name varchar unique not null primary key,
	fields hstore,
	begin_time timestamp,
	end_time timestamp,
	all_lines integer,
	missing_server_hello integer,
	missing_client_hello integer,
	established integer,
	all_ports integer,
	https_port integer,
	smtp_port integer,
	with_certs integer,
	with_sni integer,
	with_cert_and_sni integer,
	grease_conns integer,
	all_ciphers hstore,
	https_with_certs integer,
	https_with_sni integer,
	https_with_cert_and_sni integer,
	https_ciphers hstore,
	https_withcert_ciphers hstore,
	https_withcertsni_ciphers hstore,
	smtp_with_certs integer,
	smtp_with_sni integer,
	smtp_with_cert_and_sni integer,
	smtp_ciphers hstore,
	smtp_withcert_ciphers hstore,
	smtp_withcertsni_ciphers hstore,
	dh_param_sizes hstore,
	curves hstore,
	client_curves hstore,
	point_formats hstore,
	client_alpns hstore,
	server_alpns hstore,
	client_exts hstore,
	server_exts hstore,
	client_ciphers hstore,
	versions hstore,
	version_cipher hstore,
	server_versions hstore,
	client_versions hstore,
	supported_versions hstore,
	server_supported_version hstore,
	selected_version hstore,
	psk_key_exchange_modes hstore,
	client_ciphers_all hstore,
	client_extensions_all hstore,
	client_ciphers_and_extensions_all hstore,
	ticket_lifetimes hstore,
	tls_signature hstore,
	tls_signature_server hstore,
	client_key_share_groups hstore,
	server_key_share_group hstore
);
END

	for my $command ( @commands ) {
		say "Executing $command";
		my $sth = $self->db->dbh->prepare($command);
		$sth->execute;
	}
}

1;
