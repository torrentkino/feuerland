package feuerland::misc;
use warnings;
use strict;
use Net::IP;
use Regexp::IPv6 qw($IPv6_re);
use Net::CIDR::Lite;
use Socket;
use JSON;

sub print($) {
	my $words = shift;
	print "\n# $words\n";
}

sub execute($$) {
	my $exe = shift;
	my $var = shift;
	printf "%-15s %s\n", $exe, $var;
}

sub check_exe($) {
	my $file = shift;
	die "$file: $!\n" unless( -f $file );
	die "$file must be an executable\n" unless( -x $file );
}

sub isValidIPv4 {
	return $_[0] =~ /^\d+\.\d+\.\d+\.\d+$/ && inet_aton($_[0]);
}

sub isValidIPv6 {
	return $_[0] =~ /^$IPv6_re$/;
}

sub find_net_dev() {
	my $file = "/proc/net/dev";
	my @list;

	die "$file: $!\n" unless( -f $file );

	open( FH, '<', $file ) or die "$file: $!\n";
	while( <FH> ) {
		s/\n//;
		s/^\s+//;
		next unless( $_ =~ m/^(wlan|eth)\d+:/ );
		my( $dev ) = split /:/, $_; # eth0: 1 2 3
		push @list, $dev;
	}
	close( FH );

	return \@list;
}

sub unique_id($$) {
	my $cache = shift;
	my $size = shift;
	my @chars = ( "A".."Z" );
	my $buffer;
	my $counter = 0;

	do {
		$buffer = "L";
		$buffer .= $chars[rand @chars] for 1..$size;

		die "Number of chains exhausted\n" if( $counter++ > 100 );
	} while( defined $cache->{ $buffer } );

	$cache->{ $buffer } = 1;

	return $buffer;
}

sub load_json($) {
	local $/ = undef;
	my $file = shift;

	die "$file: $!\n" unless( -f $file );
	open( FH, '<', $file ) or die "$file: $!\n";
	my $data = <FH>;
	close( FH );

	return JSON->new->utf8->pretty->allow_nonref->decode( $data );
}

sub load_list($$) {
	my $conf = shift;
	my $tag = shift;
	my $file = "";
	my $aggregation = Net::CIDR::Lite->new;
	my ( @list4, @list6 );

	# Load tags from /usr/share/feuerland by default
	if( defined $conf->{"dir"} && -d $conf->{"dir"} ) {
		$file = $conf->{"dir"}."/$tag.json";
	} else {
		$file = "/usr/share/feuerland/$tag.json";
	}

	my $json = feuerland::misc::load_json( $file );

	foreach my $cidr ( keys %{$json} ) {
		next unless( $cidr =~ m/.+\/\d+$/ );
		my ( $network, $netmask ) = split /\//, $cidr;

		if( feuerland::misc::isValidIPv4( $network ) ) {
			next unless( $netmask >= 0 && $netmask <= 32 );
			$aggregation->add( $cidr );
			next;
		}

		if( feuerland::misc::isValidIPv6( $network ) ) {
			next unless( $netmask >= 0 && $netmask <= 64 );
			push @list6, $cidr;
			next;
		}
	}

	@list4 = $aggregation->list;
	return ( \@list4, \@list6 );
}

1;
