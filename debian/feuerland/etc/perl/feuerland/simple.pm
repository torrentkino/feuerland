package feuerland::simple;
use warnings;
use strict;

sub ipv6_neighbourhood($) {
	my $cmd = shift;
	my $c = $cmd->{"fw"}->{'6'};
	my $table;
	my @type;

	feuerland::misc::print( "Rule ICMPv6 Neighbourhood Discovery" );

	$table = "INPUT_IPV6_NEIGHBOURHOOD";
	@type = (
		"neighbour-solicitation",
		"neighbour-advertisement",
		"router-advertisement" );

	feuerland::misc::execute( $c, "-N $table" );
	#feuerland::misc::execute( $c, "-A $table -j LOG --log-level info --log-prefix 'IPV6_ACCEPT '" );
	foreach my $t ( @type ) {
		feuerland::misc::execute( $c, "-A $table -p icmpv6 -m icmpv6 --icmpv6-type $t -j ACCEPT" );
	}
	feuerland::misc::execute( $c, "-A $table -j RETURN" );
	feuerland::misc::execute( $c, "-A INPUT -p icmpv6 -m hl --hl-eq 255 -j $table" );

	$table = "OUTPUT_IPV6_NEIGHBOURHOOD";
	@type = (
		"neighbour-advertisement",
		"neighbour-solicitation",
		"router-solicitation" );

	feuerland::misc::execute( $c, "-N $table" );
	#feuerland::misc::execute( $c, "-A $table -j LOG --log-level info --log-prefix 'IPV6_ACCEPT '" );
	foreach my $t ( @type ) {
		feuerland::misc::execute( $c, "-A $table -p icmpv6 -m icmpv6 --icmpv6-type $t -j ACCEPT" );
	}
	feuerland::misc::execute( $c, "-A $table -j RETURN" );
	feuerland::misc::execute( $c, "-A OUTPUT -p icmpv6 -m hl --hl-eq 255 -j $table" );
}

sub ipv6_weird($) {
	my $cmd = shift;
	my $c = $cmd->{"fw"}->{'6'};

	feuerland::misc::print( "Rule \"IPv6: No Next Header\" traffic with no payload" );
	feuerland::misc::execute( $c, "-A INPUT -p ipv6-nonxt -m length --length 40 -j ACCEPT" );
}

sub established($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule Established/Related" );
	foreach my $version (keys %{ $cmd->{"fw"} } ) {
		my $c = $cmd->{"fw"}->{$version};
		feuerland::misc::execute( $c, "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" );
		feuerland::misc::execute( $c, "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" );
	}
}

sub lo($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule lo" );
	foreach my $version (keys %{ $cmd->{"fw"} } ) {
		my $c = $cmd->{"fw"}->{$version};
		feuerland::misc::execute( $c, "-A INPUT -i lo -m conntrack --ctstate NEW -j ACCEPT" );
		feuerland::misc::execute( $c, "-A OUTPUT -o lo -m conntrack --ctstate NEW -j ACCEPT" );
	}
}

sub icmp($) {
	my $cmd = shift;
	my $var = "";

	feuerland::misc::print( "Rule ICMP PING" );

	$var = "";
	$var .= "-A INPUT ";
	$var .= "-p icmp -m icmp --icmp-type echo-request ";
	$var .= "-m conntrack --ctstate NEW ";
	$var .= "-j ACCEPT";
	feuerland::misc::execute( $cmd->{"fw"}->{'4'}, $var );

	$var = "";
	$var .= "-A INPUT ";
	$var .= "-p icmpv6 -m icmpv6 --icmpv6-type echo-request ";
	$var .= "-m conntrack --ctstate NEW ";
	$var .= "-j ACCEPT";
	feuerland::misc::execute( $cmd->{"fw"}->{'6'}, $var );
}

sub mdns($) {
	my $cmd = shift;
	my @direction = ( "INPUT", "OUTPUT" );

	feuerland::misc::print( "Rule MDNS" );

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
	feuerland::misc::print( "Rule SSDP" );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N SSDP" );
	feuerland::misc::execute( $c, "-A SSDP -j LOG --log-level info --log-prefix 'SSDP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A SSDP -j ACCEPT" );
	feuerland::misc::execute( $c, "-A INPUT -p udp -m udp -d 239.255.255.250 --dport 1900 -m conntrack --ctstate NEW -j SSDP" );
}

sub dhcp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule DHCP" );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N DHCP" );
	feuerland::misc::execute( $c, "-A DHCP -j LOG --log-level info --log-prefix 'DHCP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A DHCP -j ACCEPT" );
	feuerland::misc::execute( $c,
		"-A INPUT -p udp -m udp -m multiport -d 255.255.255.255 --dports 67,68 -m conntrack --ctstate NEW -j DHCP" );
}

sub igmp($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule IGMP" );
	my $c = $cmd->{"fw"}->{'4'};
	feuerland::misc::execute( $c, "-N IGMP" );
	feuerland::misc::execute( $c, "-A IGMP -j LOG --log-level info --log-prefix 'IGMP_ACCEPT '" );
	feuerland::misc::execute( $c, "-A IGMP -j ACCEPT" );
	feuerland::misc::execute( $cmd->{"fw"}->{'4'}, "-A INPUT -p igmp -d 224.0.0.0/4 -j IGMP" );
	feuerland::misc::execute( $cmd->{"fw"}->{'4'}, "-A OUTPUT -p igmp -d 224.0.0.0/4 -j IGMP" );
}

sub broadcast($) {
	my $cmd = shift;
	feuerland::misc::print( "Rule BROADCAST" );
	my $c = $cmd->{"fw"}->{'4'};
#	feuerland::misc::execute( $c, "-A INPUT -m pkttype --pkt-type broadcast -j ACCEPT" );
#	feuerland::misc::execute( $c, "-A OUTPUT -m pkttype --pkt-type broadcast -j ACCEPT" );
	feuerland::misc::execute( $c, "-A INPUT -m addrtype --dst-type BROADCAST -j ACCEPT" );
	feuerland::misc::execute( $c, "-A OUTPUT -m addrtype --dst-type BROADCAST -j ACCEPT" );
}

sub multicast($) {
	my $cmd = shift;
	my @direction = ( "INPUT", "OUTPUT" );

	feuerland::misc::print( "Rule MULTICAST" );

	foreach my $version (keys %{ $cmd->{"fw"} } ) {
		my $c = $cmd->{"fw"}->{$version};

		foreach my $d ( @direction ) {
			#feuerland::misc::execute( $c, "-A $d -m pkttype --pkt-type multicast -j MULTICAST" );
			feuerland::misc::execute( $c, "-A $d -m addrtype --dst-type MULTICAST -j ACCEPT" );
		}
	}
}

sub final($$$) {
	my $exe = shift;
	my $conf = shift;
	my $target = shift;
	my $policy = "deny";

	feuerland::misc::print( "Rule $target" );

	# Policy: "accept" or "deny"?
	if( defined $conf->{"policy"} ) {
		if( defined $conf->{"policy"}->{lc($target)} ) {
			$policy = $conf->{"policy"}->{lc($target)};
		}
	}

	foreach my $version (keys %{ $exe->{"fw"} } ) {
		my $c = $exe->{"fw"}->{$version};

		if( feuerland::std::logging_enabled( $conf, $policy ) ) {
			feuerland::misc::execute( $c,
				"-A $target -j LOG --log-level info --log-prefix '".uc($policy)." '" );
		}

		if( $policy eq "accept" ) {
			feuerland::misc::execute( $c, "-A $target -m conntrack --ctstate NEW -j ACCEPT" );
		} else {
			feuerland::misc::execute( $c,
				"-A $target -p tcp -m tcp -j REJECT --reject-with tcp-reset" );
			feuerland::misc::execute( $c, "-A $target -j DROP" );
		}
	}
}

1;
