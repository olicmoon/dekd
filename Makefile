SUBDIRS = util daemon client crypto
.PHONY: subdirs $(SUBDIRS)

CLEANDIRS = $(SUBDIRS:%=clean-%)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean: $(CLEANDIRS)
$(CLEANDIRS):
	$(MAKE) -C $(@:clean-%=%) clean

install:
	sudo cp obj/libknox_utils.so obj/libknox_crypto.so /usr/lib
