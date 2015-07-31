package feuerland::import;
use warnings;
use strict;

use IO::Uncompress::Gunzip qw(gunzip $GunzipError) ;
use File::Temp qw/ tempfile /;
use LWP::Simple;
use Encode qw(encode);
use Net::CIDR::Lite;
use JSON;

sub print_help_iblocklist($) {
		my $opt_help = shift;

		return unless( $opt_help );

		print <<EOF
$0 \\
		-h => Help
		-l => List blocklists
		-d => Download the blocklist and print it to stdout
		-o => Write the blocklist to the current workdir
EOF
;
		exit;
}

sub print_help_ipdeny($) {
		my $opt_help = shift;

		return unless( $opt_help );

		print <<EOF
$0 \\
		-h => Help
		-d XX => Download all networks of country XX and print them to stdout
		-o => Write the list to the current workdir
EOF
;
		exit;
}

sub print_lists($$) {
	my $iblock = shift;
	my $opt_list = shift;

	return unless( $opt_list );

	foreach my $list ( sort keys %{$iblock} ) {
		print $list."\n";
	}
	exit;
}

sub print_stdout($$) {
	my $json = shift;
	my $opt_file = shift;
	return if( $opt_file );
	print $json."\n";
}

sub print_file($$$) {
	my $json = shift;
	my $name = shift;
	my $opt_file = shift;

	return unless( $opt_file );

	my $file = $name.".json";

	return if( -f $file );

	open FH, '>', $file or die "$file: $!\n";
	print FH $json;
	close FH;
}

sub download_iblocklist($$) {
	my $iblock = shift;
	my $list = shift;
	my $content;

	exit unless( $list );
	exit unless( defined $iblock->{$list} );

	my $url = "http://list.iblocklist.com/?list=";
	$url .= $iblock->{$list};
	$url .= "&fileformat=p2p&archiveformat=gz";

	# Temporary file
	my ( $fh, $file ) = tempfile();

	# Download
	my $rc = getstore( $url, $file ) or die;
	die "getstore of <$url> failed with $rc" if( is_error( $rc ) );

	# Unzip
	open FH, '<', $file or die;
	my $gzip = <FH>;
	gunzip \$gzip => \$content
		or die "gunzip failed: $GunzipError\n";
	close FH or die;

	# Cleanup
	unlink $file;

	return $content;
}

sub download_ipdeny($) {
	my $country = shift;
	my %hash;
	my ( @url, $url );

	exit unless( $country );
	die "Example: $0 -d DE\n"
		unless( $country =~ m/^[a-zA-Z][a-zA-Z]$/ );

	$url = "http://ipdeny.com/ipblocks/data/countries/";
	$url .= lc($country);
	$url .= ".zone";
	push @url, $url;

	$url = "http://ipdeny.com/ipv6/ipaddresses/blocks/";
	$url .= lc($country);
	$url .= ".zone";
	push @url, $url;

	foreach my $u (@url) {
		# Temporary file
		my ( $fh, $file ) = tempfile();

		# Download
		my $rc = getstore( $u, $file ) or die;
		if( is_error( $rc ) ) {
			print "getstore of <$u> failed with $rc\n";
			unlink $file;
			next;
		}

		# Load
		open FH, '<', $file or die;
		while( <FH> ) {
			s/\n//;
			$hash{$_} = "$country (IPdeny)";
		}
		close FH or die;

		# Cleanup
		unlink $file;
	}

	return \%hash;
}


sub cidr_converter($$) {
	my $content = shift;
	my $name = shift;
	my %hash;

	my @line = split /\n/, $content;
	foreach my $line (@line) {
		next unless( $line =~ m/:/ && $line !~ m/:.*:/ );

		my ($tag,$range) = split /:/, $line;
		my $tag_utf8 = encode('utf-8', $tag);
		$tag_utf8 =~ s/'/`/g;
		$tag_utf8 =~ s/\t//g;

		my $cidr = Net::CIDR::Lite->new;
		$cidr->add_range($range);

		foreach my $this (@{$cidr->list}) {
			$hash{$this} = "$tag ($name)";
		}
	}

	return \%hash;
}

sub json_converter($) {
	my $hash = shift;
	my $json = JSON->new->allow_nonref;
	my $pretty = $json->canonical->pretty->encode( $hash );
	return $pretty;
}

1;
