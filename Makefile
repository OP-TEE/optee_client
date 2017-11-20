# Public variables are stored in config.mk
include ./config.mk

#########################################################################
# Set Internal Variables						#
# May be modified to match your setup                                   #
#########################################################################
ifneq ($(V),1)
VPREFIX := @
endif
export VPREFIX

EXPORT_DIR ?= $(O)/export
DESTDIR ?= $(EXPORT_DIR)
BINDIR ?= /bin
LIBDIR ?= /lib
INCLUDEDIR ?= /include

CFG_TA_GPROF_SUPPORT ?= n

.PHONY: all build build-libteec install copy_export \
	clean cscope clean-cscope \
	distclean

all: build install

build-libteec:
	@echo "Building libteec.so"
	@$(MAKE) --directory=libteec --no-print-directory --no-builtin-variables \
			CFG_TEE_BENCHMARK=$(CFG_TEE_BENCHMARK)


build-tee-supplicant: build-libteec
	@echo "Building tee-supplicant"
	$(MAKE) --directory=tee-supplicant  --no-print-directory --no-builtin-variables

build: build-libteec build-tee-supplicant

install: copy_export

clean: clean-libteec clean-tee-supplicant clean-cscope

clean-libteec:
	@$(MAKE) --directory=libteec --no-print-directory clean

clean-tee-supplicant:
	@$(MAKE) --directory=tee-supplicant --no-print-directory clean

cscope:
	@echo "  CSCOPE"
	${VPREFIX}find ${CURDIR} -name "*.[chsS]" > cscope.files
	${VPREFIX}cscope -b -q -k

clean-cscope:
	${VPREFIX}rm -f cscope.*

distclean: clean

copy_export: build
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp -a ${O}/libteec/libteec.so* $(DESTDIR)$(LIBDIR)
	cp -a ${O}/libteec/libteec.a $(DESTDIR)$(LIBDIR)
	cp ${O}/tee-supplicant/tee-supplicant $(DESTDIR)$(BINDIR)
	cp public/*.h $(DESTDIR)$(INCLUDEDIR)
