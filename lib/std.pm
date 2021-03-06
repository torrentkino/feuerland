package feuerland::std;
use warnings;
use strict;

sub nft_header($) {
	my $exe = shift;
	feuerland::misc::print( "!".$exe->{"nft"}." -f", 0, 0 );
}

sub nft_init($) {
	my $exe = shift;
	feuerland::misc::print( "Init nft", 1, 1 );
	feuerland::misc::execute( $exe->{"nft"}, "add table ip filter" );
	feuerland::misc::execute( $exe->{"nft"}, "add table ip6 filter" );
}

sub nft_policy($) {
	my $exe = shift;
	feuerland::misc::print( "nft Policy", 1, 1 );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip filter INPUT { type filter hook input priority 0; policy drop; }" );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip filter FORWARD { type filter hook forward priority 0; policy drop; }" );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip filter OUTPUT { type filter hook output priority 0; policy drop; }" );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip6 filter INPUT { type filter hook input priority 0; policy drop; }" );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip6 filter FORWARD { type filter hook forward priority 0; policy drop; }" );
	feuerland::misc::execute( $exe->{"nft"}, "add chain ip6 filter OUTPUT { type filter hook output priority 0; policy drop; }" );

}

sub nft_reset($) {
	my $exe = shift;
	feuerland::misc::print( "Cleanup nft", 1, 1 );
	feuerland::misc::execute( $exe->{"nft"}, "flush ruleset" );
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

sub policy($$$$$) {
	my $exe = shift;
	my $table = shift;
	my $target = shift;
	my $policy = shift;
	my $proto = shift;

	# ACCEPT
	if( $policy eq "accept" ) {
		feuerland::misc::execute( $exe->{"nft"}, "add rule $table filter $target counter accept" );
		return;
	}

	# REJECT TCP
	if( $proto eq "tcp" ) {
		feuerland::misc::execute( $exe->{"nft"}, "add rule $table filter $target counter reject with tcp reset" );
	}

	# Port unreachable
	my $icmp_type = ( $table eq "ip6" ) ? "icmpv6" : "icmp";
	feuerland::misc::execute( $exe->{"nft"}, "add rule $table filter $target counter reject with $icmp_type type port-unreachable" );

	# Catchall
	feuerland::misc::execute( $exe->{"nft"}, "add rule $table filter $target counter drop" );
}


sub logging($$$$$$) {
	my $conf = shift;
	my $exe = shift;
	my $table = shift;
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

	feuerland::misc::execute( $exe->{"nft"},
		"add rule $table filter $target counter log prefix \"$desc \" level info" );
}

1;
