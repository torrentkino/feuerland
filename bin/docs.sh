#!/bin/sh

if [ ! $(which ronn) ]; then
	apt-cache show ruby-ronn
	echo "# sudo apt-get install ruby-ronn"
	exit
fi

ronn < README.md > debian/docs/feuerland.1

cat > debian/feuerland.manpages <<EOF
./debian/docs/feuerland.1
EOF
