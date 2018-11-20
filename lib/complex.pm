package feuerland::complex;
use warnings;
use strict;
use JSON;

sub chain($$$$$) {
	my $exe = shift;
	my $ipset = shift;
	my $conf = shift;
	my $id_cache = shift;
	my $table = shift;
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

				chain1_start( $exe, $conf, $chain1, $direction, $proto, $port, $policy, $table );

				if( defined $rules->{$direction}->{$proto}->{$port}->{'except'} ) {
					foreach my $name ( @{ $rules->{$direction}->{$proto}->{$port}->{'except'} } ) {
						my $chain2 = feuerland::misc::unique_id( $id_cache, 8 );
						chain2_start(
							$exe, $conf, $ipset, $chain1, $chain2, $direction, $proto, $port, $policy, $table, $name );
						chain1_jump_chain2(
							$exe, $ipset, $chain1, $chain2, $direction, $table, $name );
					}
				}

				chain1_stop( $exe, $conf, $chain1, $direction, $proto, $port, $policy, $table );
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
	my $table = shift;

	feuerland::misc::print(
		"Rule ".uc($direction)." / ".uc($proto)." / $port / ".uc($policy), 1, 1 );
	feuerland::misc::execute( $exe->{"nft"},
		"add chain $table filter $chain1" );
}

sub chain1_stop($$$$$$$$) {
	my $exe = shift;
	my $conf = shift;
	my $chain1 = shift;
	my $direction = shift;
	my $proto = shift;
	my $port = shift;
	my $policy = shift;
	my $table = shift;

	feuerland::std::logging( $conf, $exe, $table, $chain1, $policy, undef );
	feuerland::std::policy( $exe, $table, $chain1, $policy, $proto );
	feuerland::misc::execute( $exe->{"nft"},
		"add rule $table filter ".uc($direction)." $proto dport $port ct state new counter jump $chain1" );
}

sub chain1_jump_chain2($$$$$$$) {
	my $exe = shift;
	my $ipset = shift;
	my $chain1 = shift;
	my $chain2 = shift;
	my $direction = shift;
	my $table = shift;
	my $name = shift;
	my $match = ( $direction eq "input" ) ? "saddr" : "daddr";
	my $list = $ipset->{ $name }->{ $table }->{ "id" };

	feuerland::misc::execute( $exe->{"nft"},
		"add rule $table filter $chain1 $table $match \@$list jump $chain2" );
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
	my $table = shift;
	my $name = shift;
	my $list = $ipset->{ $name }->{ $table }->{ "id" };
	my $invert = ( $policy eq "accept" ) ? "deny" : "accept";

	feuerland::misc::execute( $exe->{"nft"},
		"add chain $table filter $chain2" );
	feuerland::std::logging( $conf, $exe, $table, $chain2, $invert, $name );
	feuerland::std::policy( $exe, $table, $chain2, $invert, $proto );
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

					my %table = (
						'ip' => \%data4,
						'ip6' => \%data6,
					);

					$ipset{ $name } = \%table;
				}
			}
		}
	}

	return \%ipset;
}

sub ipset_print($$) {
	my $exe = shift;
	my $ipset = shift;

	feuerland::misc::print( "CIDR lists", 1, 1 );

	foreach my $name ( sort keys %{ $ipset } ) {
		foreach my $table ( sort keys %{ $ipset->{ $name } } ) {
			my $data = $ipset->{ $name }->{ $table };
			my $id = $data->{"id"};
			my $list = $data->{"list"};
			my $family = ( $table eq "ip" ) ? "ipv4_addr" : "ipv6_addr";

			feuerland::misc::execute( $exe->{"nft"}, "add set $table filter $id { type $family\\; flags constant, interval\\;}" );
			next if( scalar @{ $list } == 0 );
			feuerland::misc::execute( $exe->{"nft"}, "add element $table filter $id { ".join( ',', @{ $list } )." }" );
		}
	}
}

1;
