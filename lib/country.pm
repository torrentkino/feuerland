package feuerland::country;
use warnings;
use strict;

use Regexp::IPv6 qw($IPv6_re);
use Socket;
use JSON;
use Net::Patricia;

sub json_load($) {
	my $file = shift;
	my $utf8_encoded_json_text;
	local $/;

	open FH, '<', $file or die;
	$utf8_encoded_json_text = <FH>;
	close FH or die;

	return decode_json $utf8_encoded_json_text;
}

sub cache_build() {
	my %hash;
	return \%hash;
}

sub cache_match($$$) {
	my $cache = shift;
	my $pt = shift;
	my $entity = shift;

	if ( defined $cache->{$entity} ) {
		return $cache->{$entity};
	}

	my $tag = $pt->match_string( $entity );

	if( ! defined $tag ) {
		return "??";
	}

	$cache->{$entity} = $tag;

	return $tag;
}

sub ignore_build {
	my $ig = new Net::Patricia;

	$ig->add_string( "10.0.0.0/8" );
	$ig->add_string( "172.16.0.0/12" );
	$ig->add_string( "192.168.0.0/16" );
	$ig->add_string( "193.99.144.0/24" );

	return $ig;
}

sub ignore_match($$) {
	my $ig = shift;
	my $entity = shift;

	return $ig->match_string($entity);
}

sub tree_build($) {
	my $file = shift;

	my $pt = new Net::Patricia;

	die if( ! -f $file );

	my $json = json_load( $file );

	foreach my $net (keys %{$json}) {
		$pt->add_string( $net, $json->{$net} );
	}

	return $pt;
}

sub tree_match($$$$) {
	my $pt = shift;
	my $ig = shift;
	my $entity = shift;
	my $cache = shift;

	# Patricia: ipv6 is not available
	return "--" if( ! isValidIPv4( $entity ) );

	# Ignore list
	return "xx" if( defined ignore_match( $ig, $entity ) );

	# Lookip IP
	return cache_match( $cache, $pt, $entity );
}

sub find($$$$) {
	my $ig = shift;
	my $pt = shift;
	my $src = shift;
	my $cache = shift;

	return tree_match( $pt, $ig, $src, $cache );
}

1;
