package feuerland::complex;
use warnings;
use strict;
use JSON;

sub chain($$$$$) {
	my $exe = shift;
	my $ipset = shift;
	my $conf = shift;
	my $id_cache = shift;
	my $version = shift;
	my $rules;

	return unless( defined $conf->{"rules"} );
	$rules = $conf->{"rules"};

	foreach my $direction ( keys %{ $rules } ) {
		next unless( $direction =~ m/^(input|output)$/ );

		foreach my $proto ( keys %{ $rules->{$direction} } ) {
			next unless( $proto =~ m/^(tcp|udp)$/ );

			foreach my $port ( keys %{ $rules->{$direction}->{$proto} } ) {
				next unless( $port =~ m/^\d+$/ );
				next unless( defined $rules->{$direction}->{$proto}->{$port}->{'policy'} );
				my $policy = $rules->{$direction}->{$proto}->{$port}->{'policy'};
				next unless( $policy =~ m/^(accept|deny)$/ );
				my $chain1 = feuerland::misc::unique_id( $id_cache, 8 );

				chain1_start( $exe, $conf, $chain1, $direction, $proto, $port, $policy, $version );

				if( defined $rules->{$direction}->{$proto}->{$port}->{'except'} ) {
					foreach my $name ( @{ $rules->{$direction}->{$proto}->{$port}->{'except'} } ) {
						my $chain2 = feuerland::misc::unique_id( $id_cache, 8 );
						chain2_start(
							$exe, $conf, $ipset, $chain1, $chain2, $direction, $proto, $port, $policy, $version, $name );
						chain1_jump_chain2(
							$exe, $ipset, $chain1, $chain2, $direction, $version, $name );
					}
				}

				chain1_stop( $exe, $conf, $chain1, $direction, $proto, $port, $policy, $version );
			}
		}
	}
}

sub chain1_start($$$$$$$$) {
	my $exe = shift;
	my $conf = shift;
	my $chain1 = shift;
	my $direction = shift;
	my $proto = shift;
	my $port = shift;
	my $policy = shift;
	my $version = shift;

	feuerland::misc::print(
		"Rule ".uc($direction)." / ".uc($proto)." / $port / ".uc($policy) );
	if ( $version == 4 ) {
		feuerland::misc::execute( $exe->{"nft"},
			"add chain ip filter $chain1" );
	} else {
		feuerland::misc::execute( $exe->{"nft"},
			"add chain ip6 filter $chain1" );
	}
}

sub chain1_stop($$$$$$$$) {
	my $exe = shift;
	my $conf = shift;
	my $chain1 = shift;
	my $direction = shift;
	my $proto = shift;
	my $port = shift;
	my $policy = shift;
	my $version = shift;

	if( $version == 4 ) {
		feuerland::std::logging( $conf, $exe, "ip", $chain1, $policy, undef );
		feuerland::std::policy( $exe, "ip", $chain1, $policy, $proto );
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip filter ".uc($direction)." $proto dport $port ct state new counter jump $chain1" );
	} else {
		feuerland::std::logging( $conf, $exe, "ip6", $chain1, $policy, undef );
		feuerland::std::policy( $exe, "ip6", $chain1, $policy, $proto );
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip6 filter ".uc($direction)." $proto dport $port ct state new counter jump $chain1" );
	}
}

sub chain1_jump_chain2($$$$$$$) {
	my $exe = shift;
	my $ipset = shift;
	my $chain1 = shift;
	my $chain2 = shift;
	my $direction = shift;
	my $version = shift;
	my $name = shift;
	my $match = ( $direction eq "input" ) ? "saddr" : "daddr";
	my $list = $ipset->{ $name }->{ $version }->{ "id" };

	if ( $version == 4 ) {
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip filter $chain1 ip $match \@$list jump $chain2" );
	} else {
		feuerland::misc::execute( $exe->{"nft"},
			"add rule ip6 filter $chain1 ip6 $match \@$list jump $chain2" );
	}
}

sub chain2_start($$$$$$$$$$$) {
	my $exe = shift;
	my $conf = shift;
	my $ipset = shift;
	my $chain1 = shift;
	my $chain2 = shift;
	my $direction = shift;
	my $proto = shift;
	my $port = shift;
	my $policy = shift;
	my $version = shift;
	my $name = shift;
	my $list = $ipset->{ $name }->{ $version }->{ "id" };
	my $invert = ( $policy eq "accept" ) ? "deny" : "accept";

	if ( $version == 4 ) {
		feuerland::misc::execute( $exe->{"nft"},
			"add chain ip filter $chain2" );
		feuerland::std::logging( $conf, $exe,"ip", $chain2, $invert, $name );
		feuerland::std::policy( $exe, "ip", $chain2, $invert, $proto );
	} else {
		feuerland::misc::execute( $exe->{"nft"},
			"add chain ip6 filter $chain2" );
		feuerland::std::logging( $conf, $exe,"ip6", $chain2, $invert, $name );
		feuerland::std::policy( $exe, "ip6", $chain2, $invert, $proto );
	}

}

sub ipset_load($$) {
	my $conf = shift;
	my $id_cache = shift;
	my %ipset;

	return unless( defined $conf->{"rules"} );
	my $rules = $conf->{"rules"};

	foreach my $direction ( keys %{ $rules } ) {
		next unless( $direction =~ m/^(input|output)$/ );

		foreach my $proto ( keys %{ $rules->{$direction} } ) {
			next unless( $proto =~ m/^(tcp|udp)$/ );

			foreach my $port ( keys %{ $rules->{$direction}->{$proto} } ) {
				next unless( $port =~ m/^\d+$/ );
				next unless( defined $rules->{$direction}->{$proto}->{$port}->{'except'} );

				foreach my $name ( @{ $rules->{$direction}->{$proto}->{$port}->{'except'} } ) {
					next if( defined $ipset{ $name } );

					my $unique = feuerland::misc::unique_id( $id_cache, 7 );

					my ( $list4, $list6 ) = feuerland::misc::load_list( $conf, $name );

					my %data4 = (
						"id" => $unique."4",
						"list" => $list4,
					);

					my %data6 = (
						"id" => $unique."6",
						"list" => $list6,
					);

					my %version = (
						'4' => \%data4,
						'6' => \%data6,
					);

					$ipset{ $name } = \%version;
				}
			}
		}
	}

	return \%ipset;
}

sub ipset_print($$) {
	my $exe = shift;
	my $ipset = shift;

	feuerland::misc::print( "CIDR lists" );

	foreach my $name ( sort keys %{ $ipset } ) {
		foreach my $version ( sort keys %{ $ipset->{ $name } } ) {
			my $data = $ipset->{ $name }->{ $version };
			my $id = $data->{"id"};
			my $list = $data->{"list"};
			my $family = ( $version == 4 ) ? "ipv4_addr" : "ipv6_addr";
			my $table = ( $version == 4 ) ? "ip" : "ip6";

			feuerland::misc::execute( $exe->{"nft"}, "add set $table filter $id { type $family\\; flags constant, interval\\;}" );
			next if( scalar @{ $list } == 0 );
			feuerland::misc::execute( $exe->{"nft"}, "add element $table filter $id { ".join( ',', @{ $list } )." }" );
		}
	}
}

1;
