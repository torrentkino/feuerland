package feuerland::simple;
use warnings;
use strict;

sub ipv6_neighbourhood($) {
	my $cmd = shift;
	my $c = $cmd->{"fw"}->{'6'};
	my $table;
	my @type;

	feuerland::misc::print( "Rule ICMPv6 Neighbourhood Discovery", 1, 1 );

	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT icmpv6 type { nd-neighbor-advert, nd-neighbor-solicit, nd-router-advert} ip6 hoplimit 255 accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter OUTPUT icmpv6 type { nd-neighbor-advert, nd-neighbor-solicit, nd-router-advert} ip6 hoplimit 255 accept" );
}

sub ipv6_weird($) {
	my $cmd = shift;

	feuerland::misc::print( "Rule \"IPv6: No Next Header\" traffic with no payload", 1, 1 );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT meta l4proto ipv6-nonxt meta length 40 counter accept" );
}

sub established($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule Established/Related", 1, 1 );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter INPUT ct state related,established counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter OUTPUT ct state related,established counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT ct state related,established counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter OUTPUT ct state related,established counter accept" );
}

sub lo($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule lo", 1, 1 );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter INPUT iifname lo ct state new counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter OUTPUT oifname lo ct state new counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT iifname lo ct state new counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter OUTPUT oifname lo ct state new counter accept" );
}

sub icmp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule ICMP PING", 1, 1 );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter INPUT icmp type echo-request ct state new counter accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT icmpv6 type echo-request ct state new counter accept" );
}

sub mdns($) {
	my $cmd = shift;
	my @direction = ( "INPUT", "OUTPUT" );

	feuerland::misc::print( "Rule MDNS", 1, 1 );

	foreach my $version (keys %{ $cmd->{"fw"} } ) {
		my $c = $cmd->{"fw"}->{$version};
		feuerland::misc::execute( $c, "-N MDNS" );
		feuerland::misc::execute( $c, "-A MDNS -j LOG --log-level info --log-prefix 'MDNS_ACCEPT '" );
		feuerland::misc::execute( $c, "-A MDNS -j ACCEPT" );
	}

	foreach my $d ( @direction ) {
		feuerland::misc::execute( $cmd->{"fw"}->{'4'},
			"-A $d -p udp -m udp -d 224.0.0.251 --dport 5353 -m conntrack --ctstate NEW -j MDNS" );
		feuerland::misc::execute( $cmd->{"fw"}->{'6'},
			"-A $d -p udp -m udp -d ff02::fb --dport 5353 -m conntrack --ctstate NEW -j MDNS" );
	}
}

sub ssdp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule SSDP", 1, 1 );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N SSDP" );
	feuerland::misc::execute( $c, "-A SSDP -j LOG --log-level info --log-prefix 'SSDP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A SSDP -j ACCEPT" );
	feuerland::misc::execute( $c, "-A INPUT -p udp -m udp -d 239.255.255.250 --dport 1900 -m conntrack --ctstate NEW -j SSDP" );
}

sub dhcp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule DHCP", 1, 1 );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N DHCP" );
	feuerland::misc::execute( $c, "-A DHCP -j LOG --log-level info --log-prefix 'DHCP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A DHCP -j ACCEPT" );
	feuerland::misc::execute( $c,
		"-A INPUT -p udp -m udp -m multiport -d 255.255.255.255 --dports 67,68 -m conntrack --ctstate NEW -j DHCP" );
}

sub igmp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule IGMP", 1, 1 );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N IGMP" );
	feuerland::misc::execute( $c, "-A IGMP -j LOG --log-level info --log-prefix 'IGMP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A IGMP -j ACCEPT" );
	feuerland::misc::execute( $cmd->{"fw"}->{'4'}, "-A INPUT -p igmp -d 224.0.0.0/4 -j IGMP" );
	feuerland::misc::execute( $cmd->{"fw"}->{'4'}, "-A OUTPUT -p igmp -d 224.0.0.0/4 -j IGMP" );
}

sub broadcast($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule Multicast/Broadcast", 1, 1 );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter INPUT meta pkttype { multicast } accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip6 filter OUTPUT meta pkttype { multicast } accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter INPUT meta pkttype { broadcast, multicast } accept" );
	feuerland::misc::execute( $cmd->{"nft"}, "add rule ip filter OUTPUT meta pkttype { broadcast, multicast } accept" );
}

sub final($$$) {
	my $exe = shift;
	my $conf = shift;
	my $target = shift;
	my $policy = "deny";

	feuerland::misc::print( "Rule $target", 1, 1 );

	# Policy: "accept" or "deny"?
	if( defined $conf->{"policy"} ) {
		if( defined $conf->{"policy"}->{lc($target)} ) {
			$policy = $conf->{"policy"}->{lc($target)};
		}
	}

	if( feuerland::std::logging_enabled( $conf, $policy ) ) {
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip filter $target counter log prefix \"".uc($policy)." \" level info" );
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip6 filter $target counter log prefix \"".uc($policy)." \" level info" );
	}

	if( $policy eq "accept" ) {
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip filter $target ct state new counter accept" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip6 filter $target ct state new counter accept" );
	} else {
		#feuerland::misc::execute( $exe->{"nft"}, "add rule ip filter $target ip protocol udp reject" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip filter $target counter reject with tcp reset" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip filter $target counter reject with icmp type prot-unreachable" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip filter $target counter drop" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip6 filter $target counter reject with tcp reset" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip6 filter $target counter reject with icmpv6 type port-unreachable" );
		feuerland::misc::execute( $exe->{"nft"}, "add rule ip6 filter $target counter drop" );
	}
}

1;
