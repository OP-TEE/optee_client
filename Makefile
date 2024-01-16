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
SBINDIR ?= /usr/sbin
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include
sbindir ?= $(SBINDIR)
libdir ?= $(LIBDIR)
includedir ?= $(INCLUDEDIR)

WITH_TEEACL ?= 1

.PHONY: all build build-libteec build-libckteec build-libseteec \
	build-libteeacl install copy_export clean cscope \
	clean-cscope \
	checkpatch-pre-req checkpatch-modified-patch checkpatch-modified-file \
	checkpatch-last-commit-patch checkpatch-last-commit-file \
	checkpatch-base-commit-patch checkpatch-base-commit-file \
	checkpatch-all-files distclean

all: build install

build-libteec:
	@echo "Building libteec.so"
	@$(MAKE) --directory=libteec --no-print-directory --no-builtin-variables \
			CFG_TEE_CLIENT_LOG_LEVEL=$(CFG_TEE_CLIENT_LOG_LEVEL)

build-tee-supplicant: build-libteec
	@echo "Building tee-supplicant"
	$(MAKE) --directory=tee-supplicant  --no-print-directory --no-builtin-variables CFG_TEE_SUPP_LOG_LEVEL=$(CFG_TEE_SUPP_LOG_LEVEL)

build: build-libteec build-tee-supplicant build-libckteec build-libseteec
ifeq ($(WITH_TEEACL),1)
build: build-libteeacl
endif

build-libckteec: build-libteec
	@echo "Building libckteec.so"
	@$(MAKE) --directory=libckteec --no-print-directory --no-builtin-variables

build-libseteec: build-libteec
	@echo "Building libseteec.so"
	@$(MAKE) --directory=libseteec --no-print-directory --no-builtin-variables

build-libteeacl:
	@echo "Building libteeacl.so"
	@$(MAKE) --directory=libteeacl --no-print-directory --no-builtin-variables

install: copy_export

clean: clean-libteec clean-tee-supplicant clean-cscope clean-libckteec \
	clean-libseteec
ifeq ($(WITH_TEEACL),1)
clean: clean-libteeacl
endif

clean-libteec:
	@$(MAKE) --directory=libteec --no-print-directory clean

clean-tee-supplicant:
	@$(MAKE) --directory=tee-supplicant --no-print-directory clean

clean-libckteec:
	@$(MAKE) --directory=libckteec --no-print-directory clean

clean-libseteec:
	@$(MAKE) --directory=libseteec --no-print-directory clean

clean-libteeacl:
	@$(MAKE) --directory=libteeacl --no-print-directory clean

cscope:
	@echo "  CSCOPE"
	${VPREFIX}find ${CURDIR} -name "*.[chsS]" > cscope.files
	${VPREFIX}cscope -b -q -k

clean-cscope:
	${VPREFIX}rm -f cscope.*

# Various checkpatch targets. The ones ending with "patch" only considers the
# patch, whilst the ones ending with "file" checks the complete file.
# +-------------------------------+------------+----------------------------+
# | Target commit                 | File/Patch | Comment                    |
# +-------------------------------+------------+----------------------------+
# | checkpatch-modified-patch     | Patch      | Check local modifications  |
# +-------------------------------+------------+----------------------------+
# | checkpatch-modified-file      | File       | Check Local modifications  |
# +-------------------------------+------------+----------------------------+
# | checkpatch-last-commit-patch  | Patch      | Check against HEAD^        |
# +-------------------------------+------------+----------------------------+
# | checkpatch-last-commit-file   | File       | Check against HEAD^        |
# +-------------------------------+------------+----------------------------+
# | checkpatch-base-commit-patch  | Patch      | Against specic commit      |
# +-------------------------------+------------+----------------------------+
# | checkpatch-base-commit-file   | File       | Against specic commit      |
# +-------------------------------+------------+----------------------------+
# | checkpatch-all-files          | File       | Check all tracked files    |
# +-------------------------------+------------+----------------------------+
CHECKPATCH_IGNORE	?= --ignore NEW_TYPEDEFS --no-signoff
CHECKPATCH_STRICT	?= --strict
CHECKPATCH_ARGS		?= $(CHECKPATCH_IGNORE) $(CHECKPATCH_STRICT) --no-tree --terse
CHECKPATCH_PATCH_ARGS   := $(CHECKPATCH_ARGS) --patch
CHECKPATCH_FILE_ARGS 	:= $(CHECKPATCH_ARGS) --file --no-patch

checkpatch-pre-req:
	@echo "  CHECKPATCH"
ifndef CHECKPATCH
	$(error "Environment variable CHECKPATCH must point to Linux kernels checkpatch script")
else
ifeq (,$(wildcard ${CHECKPATCH}))
	$(error "CHECKPATCH points to the incorrect file")
endif
endif

checkpatch-modified-patch: checkpatch-pre-req
	${VPREFIX}git diff | ${CHECKPATCH} $(CHECKPATCH_PATCH_ARGS) - || true

checkpatch-modified-file: checkpatch-pre-req
	${VPREFIX}${CHECKPATCH} $(CHECKPATCH_FILE_ARGS) $(shell git diff --name-only)


checkpatch-last-commit-patch: checkpatch-pre-req
	${VPREFIX}git diff HEAD^ | ${CHECKPATCH} $(CHECKPATCH_PATCH_ARGS) - || true

checkpatch-last-commit-file: checkpatch-pre-req
	${VPREFIX}${CHECKPATCH} $(CHECKPATCH_FILE_ARGS) $(shell git diff --name-only HEAD^)


checkpatch-base-commit-patch: checkpatch-pre-req
ifndef BASE_COMMIT
	$(error "Environment variable BASE_COMMIT must contain a valid commit")
endif
	${VPREFIX}git diff $(BASE_COMMIT) | ${CHECKPATCH} $(CHECKPATCH_PATCH_ARGS) - || true

checkpatch-base-commit-file: checkpatch-pre-req
ifndef BASE_COMMIT
	$(error "Environment variable BASE_COMMIT must contain a valid commit")
endif
	${VPREFIX}${CHECKPATCH} $(CHECKPATCH_FILE_ARGS) $(shell git diff --name-only ${BASE_COMMIT})

checkpatch-all-files: checkpatch-pre-req
	${VPREFIX}${CHECKPATCH} $(CHECKPATCH_FILE_ARGS) $(shell git ls-files)

distclean: clean

copy_export: build
	mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(libdir) $(DESTDIR)$(includedir)
	cp config.mk $(DESTDIR)/$(includedir)/optee_client_config.mk
	cp -d ${O}/libteec/libteec.so* $(DESTDIR)$(libdir)
	cp -d ${O}/libteec/libteec.a $(DESTDIR)$(libdir)
	cp ${O}/tee-supplicant/tee-supplicant $(DESTDIR)$(sbindir)
	cp libteec/include/*.h $(DESTDIR)$(includedir)
	cp libckteec/include/*.h $(DESTDIR)$(includedir)
	cp -d ${O}/libckteec/libckteec.so* $(DESTDIR)$(libdir)
	cp -d ${O}/libckteec/libckteec.a $(DESTDIR)$(libdir)
ifeq ($(WITH_TEEACL),1)
	cp libteeacl/include/*.h $(DESTDIR)$(includedir)
	cp -d ${O}/libteeacl/libteeacl.so* $(DESTDIR)$(libdir)
	cp -d ${O}/libteeacl/libteeacl.a $(DESTDIR)$(libdir)
endif
	cp libseteec/include/*.h $(DESTDIR)$(includedir)
	cp -d ${O}/libseteec/libseteec.so* $(DESTDIR)$(libdir)
	cp -d ${O}/libseteec/libseteec.a $(DESTDIR)$(libdir)
