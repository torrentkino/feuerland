package feuerland::std;
use warnings;
use strict;

sub policy($$$$) {
	my $c = shift;
	my $target = shift;
	my $policy = shift;
	my $proto = shift;

	# ACCEPT
	if( $policy eq "accept" ) {
		feuerland::misc::execute( $c, "-A $target -j ACCEPT" );
		return;
	}

	# REJECT TCP
	if( $proto eq "tcp" ) {
		my $reset = "-p tcp -m tcp -j REJECT --reject-with tcp-reset";
		feuerland::misc::execute( $c, "-A $target $reset" );
	}

	# DROP ALL
	feuerland::misc::execute( $c, "-A $target -j DROP" );
}

sub reset_ipset($) {
	my $exe = shift;
	feuerland::misc::print( "Cleanup ipset" );
	feuerland::misc::execute( $exe->{"ips"}, "destroy" );
}

sub reset_chain($) {
	my $exe = shift;
	my $file = "/proc/net/ip_tables_names";
	my @action = ( "-F", "-X", "-Z" );
	my @chain = ( "OUTPUT", "INPUT", "FORWARD" );

	feuerland::misc::print( "Default Policy" );
	foreach my $v ( 4, 6 ) {
		foreach my $c ( @chain ) {
			feuerland::misc::execute( $exe->{"fw"}->{$v}, "-P $c DROP" );
		}
	}

	feuerland::std::reset_tables( $exe );
}

sub reset_tables($) {
	my $exe = shift;
	my $file = "/proc/net/ip_tables_names";
	my @action = ( "-F", "-X", "-Z" );

	feuerland::misc::print( "Cleanup default table" );
	foreach my $v ( 4, 6 ) {
		foreach my $a ( @action ) {
			feuerland::misc::execute( $exe->{"fw"}->{$v}, $a );
		}
	}

	return unless( -f $file );

	feuerland::misc::print( "Cleanup other tables" );
	open( FH, '<', $file )
		or print "# $file : $! (sudo?)\n"
		and return;
	while( <FH> ) {
		s/\n//;

		foreach my $v ( 4, 6 ) {
			foreach my $a ( @action ) {
				feuerland::misc::execute( $exe->{"fw"}->{$v}, "-t $_ ".$a );
			}
		}
	}
	close FH;
}

sub logging_enabled($$) {
	my $conf = shift;
	my $policy = shift;

	# Logging enabled for "accept" or "deny"?
	if( defined $conf->{"log"} ) {
		my %global_log_policy = map { $_ => 1 } @{ $conf->{"log"} };

		# Logging enabled for this $policy?
		if( !defined $global_log_policy{ $policy } ) {
			return 0;
		}
	}

	return 1;
}

sub logging($$$$$) {
	my $conf = shift;
	my $c = shift;
	my $target = shift;
	my $policy = shift;
	my $list = shift;
	my $buffer = "";

	return unless( logging_enabled( $conf, $policy ) );

	if( $policy eq "accept" ) {
		$buffer = "ACCEPT";
	} else {
		$buffer = "DENY";
	}

	if( defined $list ) {
		# Remove directory from list name
		$list =~ s/.*\///;
		# Attach the list name to the log messages
		$buffer .= "_$list"
	}

	# iptables has low limits
	my $desc = substr $buffer, 0, 25;

	feuerland::misc::execute( $c, "-A $target -j LOG --log-level info --log-prefix '$desc '" );
}

1;
