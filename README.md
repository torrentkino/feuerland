feuerland(1) -- Botnet Defense
==============================

## DESCRIPTION

	* Status: Proof of concept

## INSTALLATION

	* apt-get install iptables ipset libnet-ipv6addr-perl libnet-patricia-perl libregexp-ipv6-perl libjson-perl libnet-ip-perl
	* sudo make install # Just a bunch of copy statements

Or

	* make debian # This command creates an installable package for Debian
	* make ubuntu # This command creates an installable package for Ubuntu

## USAGE

	* Go to /etc/feuerland and copy one of the examples to /etc/feuerland/config.json
	* Run `feuerland`. The firewall script gets printed to stdout.
	* Run `sudo feuerland | sudo bash` to install the script.
	* Run `dmesg | feuerlog -n` to see what is going on.
	* Use `feuerland_iblocklist` and `feuerland_ipdeny` to download newer blocklists.
	* Use `feuerlist --target apache24 ipdeny/DE rfc1918 localhost` to create an Apache-2.4 ACL

