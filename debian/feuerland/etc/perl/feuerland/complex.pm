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
	feuerland::misc::execute( $exe->{"fw"}->{$version},
		"-N $chain1" );
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

	feuerland::std::logging( $conf, $exe->{"fw"}->{$version}, $chain1, $policy, undef );
	feuerland::std::policy( $exe->{"fw"}->{$version}, $chain1, $policy, $proto );
	feuerland::misc::execute( $exe->{"fw"}->{$version},
		"-A ".uc($direction)." -p $proto -m $proto --dport $port -m conntrack --ctstate NEW -j $chain1" );
}

sub chain1_jump_chain2($$$$$$$) {
	my $exe = shift;
	my $ipset = shift;
	my $chain1 = shift;
	my $chain2 = shift;
	my $direction = shift;
	my $version = shift;
	my $name = shift;
	my $match = ( $direction eq "input" ) ? "src" : "dst";
	my $list = $ipset->{ $name }->{ $version }->{ "id" };

	feuerland::misc::execute( $exe->{"fw"}->{$version},
		"-A $chain1 -m set --match-set $list $match -j $chain2" );
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

	feuerland::misc::execute( $exe->{"fw"}->{$version}, "-N $chain2" );
	feuerland::std::logging( $conf, $exe->{"fw"}->{$version}, $chain2, $invert, $name );
	feuerland::std::policy( $exe->{"fw"}->{$version}, $chain2, $invert, $proto );
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
						"id" => "4".$unique,
						"list" => $list4,
					);

					my %data6 = (
						"id" => "6".$unique,
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

	feuerland::misc::print( "IPSET exception lists" );

	foreach my $name ( sort keys %{ $ipset } ) {
		foreach my $version ( sort keys %{ $ipset->{ $name } } ) {
			my $data = $ipset->{ $name }->{ $version };
			my $id = $data->{"id"};
			my $list = $data->{"list"};
			my $family = ( $version == 4 ) ? "inet" : "inet6";

			feuerland::misc::execute( $exe->{"ips"}, "create $id hash:net family $family" );
			foreach my $cidr ( @{ $list } ) {
				feuerland::misc::execute( $exe->{"ips"}, "add $id $cidr" );
			}
		}
	}
}

1;
