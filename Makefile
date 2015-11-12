SUBDIRS =

.PHONY : all clean install docs debian ubuntu $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

install:
	mkdir -p $(DESTDIR)/etc/feuerland
	mkdir -p $(DESTDIR)/etc/perl/feuerland
	mkdir -p $(DESTDIR)/usr/share/feuerland
	cp -f bin/feuerland $(DESTDIR)/usr/bin/feuerland
	cp -f bin/feuerlist $(DESTDIR)/usr/bin/feuerlist
	cp -f bin/feuerland_iblocklist $(DESTDIR)/usr/bin/feuerland_iblocklist
	cp -f bin/feuerland_ipdeny $(DESTDIR)/usr/bin/feuerland_ipdeny
	cp -f bin/feuerlog $(DESTDIR)/usr/bin/feuerlog
	cp -n docs/* $(DESTDIR)/etc/feuerland/
	cp -rf lists/* $(DESTDIR)/usr/share/feuerland/
	cp -rf lib/feuerland/* $(DESTDIR)/etc/perl/feuerland/

docs:
	./bin/docs.sh

debian:
	./bin/debian.sh

ubuntu:
	./bin/debian.sh

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) clean -C $$dir; \
	done
