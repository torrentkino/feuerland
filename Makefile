SUBDIRS =

.PHONY : all clean install docs debian ubuntu $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

install:
	mkdir -p $(DESTDIR)/etc/feuerland
	mkdir -p $(DESTDIR)/etc/perl/feuerland
	mkdir -p $(DESTDIR)/usr/share/feuerland
	mkdir -p $(DESTDIR)/usr/lib/feuerland
	cp -f perl/feuerland $(DESTDIR)/usr/bin/feuerland
	cp -f perl/feuerlist $(DESTDIR)/usr/bin/feuerlist
	cp -f perl/feuerlog $(DESTDIR)/usr/bin/feuerlog
	cp -n docs/* $(DESTDIR)/etc/feuerland/
	cp -rf lists/* $(DESTDIR)/usr/share/feuerland/
	cp -rf lib/* $(DESTDIR)/usr/lib/feuerland/

docs:
	./bin/docs.sh

debian:
	./bin/debian.sh

ubuntu:
	./bin/debian.sh

ipdeny:
	./bin/feuerland_ipdeny

iblocklist:
	./bin/feuerland_iblocklist

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) clean -C $$dir; \
	done
