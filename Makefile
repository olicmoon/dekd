SUBDIRS = util daemon client
.PHONY: subdirs $(SUBDIRS)

CLEANDIRS = $(SUBDIRS:%=clean-%)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean: $(CLEANDIRS)
$(CLEANDIRS):
	$(MAKE) -C $(@:clean-%=%) clean
