RIVETCGI_VERS = 0.5.0.3157
KITCREATOR_VERS = 0.10.0
TCL_VERS = 8.6.6
TCLKIT = archive/kit

all: identify-user.cgi

archive/rivetcgi-$(RIVETCGI_VERS).tar.gz:
	@-mkdir archive >/dev/null 2>/dev/null
	wget -O "$@.new" http://www.rkeene.org/devel/rivetcgi-$(RIVETCGI_VERS).tar.gz
	gzip -dc "$@.new" | tar -tf - >/dev/null
	mv "$@.new" "$@"

archive/kitcreator-$(KITCREATOR_VERS).tar.gz:
	@-mkdir archive >/dev/null 2>/dev/null
	if [ "$(KITCREATOR_VERS)" = 'trunk' ]; then \
		wget -O "$@.new" "http://kitcreator.rkeene.org/fossil/tarball/kitcreator-trunk.tar.gz?uuid=trunk"; \
	else \
		wget -O "$@.new" "http://www.rkeene.org/devel/kitcreator-$(KITCREATOR_VERS).tar.gz"; \
	fi
	gzip -dc "$@.new" | tar -tf - >/dev/null
	mv "$@.new" "$@"

archive/rivetcgi/bin/rivet2starkit archive/rivetcgi/rivet-starkit/sdx.kit: archive/rivetcgi-$(RIVETCGI_VERS).tar.gz
	rm -rf archive/rivetcgi
	mkdir archive/rivetcgi && cd archive/rivetcgi && gzip -dc "../../$^" | tar -xf -
	mv archive/rivetcgi/rivetcgi-$(RIVETCGI_VERS)/* archive/rivetcgi/
	rm -rf archive/rivetcgi/rivetcgi-$(RIVETCGI_VERS)
	touch archive/rivetcgi/bin/rivet2starkit archive/rivetcgi/rivet-starkit/sdx.kit

$(TCLKIT): archive/kitcreator-$(KITCREATOR_VERS).tar.gz
	rm -rf archive/kitcreator
	mkdir archive/kitcreator && cd archive/kitcreator && gzip -dc "../../$^" | tar -xf -
	mv archive/kitcreator/kitcreator-$(KITCREATOR_VERS)/* archive/kitcreator/
	rm -rf archive/kitcreator/kitcreator-$(KITCREATOR_VERS)
	if [ -x archive/kitcreator/build/pre.sh ]; then cd archive/kitcreator && ./build/pre.sh; fi
	curl 'https://kitcreator.rkeene.org/fossil/raw/tls/build.sh?name=bd7a6635803a869d5dd4200ac9662fb7ca2b9f16' > archive/kitcreator/tls/build.sh
	cd archive/kitcreator && STATICTLS='1' KITCREATOR_PKGS='mk4tcl tcllib' MAKEFLAGS='' DESTDIR='' ./kitcreator $(TCL_VERS) --enable-threads
	cp archive/kitcreator/tclkit-$(TCL_VERS) $(TCLKIT)

identify-user.kit: archive/rivetcgi/bin/rivet2starkit $(TCLKIT) $(shell find app lib -type f)
	archive/rivetcgi/bin/rivet2starkit $(shell readlink -f "$(TCLKIT)") "$@" app lib:lib

identify-user.cgi: identify-user.kit $(TCLKIT) archive/rivetcgi/rivet-starkit/sdx.kit
	cp $(TCLKIT) $(TCLKIT).tmp
	rm -rf identify-user.vfs
	$(TCLKIT) archive/rivetcgi/rivet-starkit/sdx.kit unwrap identify-user.kit
	$(TCLKIT) archive/rivetcgi/rivet-starkit/sdx.kit wrap identify-user.cgi -runtime $(TCLKIT).tmp
	rm -f $(TCLKIT).tmp
	rm -rf identify-user.vfs

certs/completed: $(shell echo certs.in/*)
	-mkdir certs
	rm -f certs/completed
	for file in certs.in/*; do \
		hash="$$(openssl x509 -subject_hash -in "$${file}" -noout)"; \
		for try in 0 1 2 3 4 5 6 8 9; do ln "$${file}" "certs/$${hash}.$${try}" && break; done; \
	done
	touch certs/completed

install: identify-user.cgi certs/completed
	mkdir -p $(DESTDIR)/opt/identity-mgmt
	mkdir -p $(DESTDIR)/opt/identity-mgmt/web
	mkdir -p $(DESTDIR)/opt/identity-mgmt/etc
	mkdir -p $(DESTDIR)/opt/identity-mgmt/etc/client-ca
	cp identify-user.cgi $(DESTDIR)/opt/identity-mgmt/web
	cp certs/* $(DESTDIR)/opt/identity-mgmt/etc/client-ca
	chmod 755 $(DESTDIR)/opt/identity-mgmt/web
	chmod 755 $(DESTDIR)/opt/identity-mgmt/web/identify-user.cgi
	chmod 755 $(DESTDIR)/opt/identity-mgmt/etc
	chmod 755 $(DESTDIR)/opt/identity-mgmt/etc/client-ca
	chmod 644 $(DESTDIR)/opt/identity-mgmt/etc/client-ca/*

clean:
	rm -f identify-user.cgi identify-user.kit
	rm -f "$(TCLKIT).tmp" "$(TCLKIT).new"
	rm -f archive/rivetcgi-$(RIVETCGI_VERS).tar.gz.new archive/kitcreator-$(KITCREATOR_VERS).tar.gz.new
	rm -rf certs
	rm -rf identify-user.vfs

distclean: clean
	rm -rf archive

.PHONY: all clean distclean
