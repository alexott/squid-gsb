MAINTAINERCLEANFILES = Makefile.in squid-gsb.conf 

DATATOPDIR = @CONFDIR@
LSTATEDIR = @LSTATEDIR@

FLISTS = squid-gsb.conf
extra_DIST = squid-gsb.conf.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(LSTATEDIR) && \
	$(mkinstalldirs) $(DESTDIR)$(DATATOPDIR) && \
	for l in $(FLISTS) ; do \
		if [ -f $(DESTDIR)$(DATATOPDIR)/$$l ] ; then \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l.new"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l.new ; \
	  else \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l; \
		fi \
	done 

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DATATOPDIR)/$$l ; \
	done
