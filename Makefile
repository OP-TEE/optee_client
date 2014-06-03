# Define specific repositories
CFG_TEE_TEEC_GENERIC_PATH	?= $(abspath .)
CFG_TEE_TEEC_SPECIFIC_PATH	?= $(abspath .)
export CFG_TEE_TEEC_GENERIC_PATH
export CFG_TEE_TEEC_SPECIFIC_PATH

# Public variables are stored in config.mk
include $(CFG_TEE_TEEC_SPECIFIC_PATH)/config.mk

#########################################################################
# Set Internal Variables						#
# May be modified to match your setup                                   #
#########################################################################
BUILD_VERBOSE	?= 0
VPREFIX		?= @
ifeq ($(BUILD_VERBOSE),1)
VPREFIX:=
endif
export VPREFIX

CURRENTDIR	:= $(abspath .)
FORESTROOT_DIR	:= ${CURRENTDIR}/..
CROSS_PREFIX	?= ${ARM_GCC_PREFIX}
export FORESTROOT_DIR

# Path to the arm compiler
TOOLCHAINPATH	= ${ARM_TOOLCHAIN_DIR}

.PHONY: all build build-libteec install copy copy_public copy_rootfs \
	clean cscope clean-cscope \
	checkpatch-pre-req checkpatch-modified-patch checkpatch-modified-file \
	checkpatch-last-commit-patch checkpatch-last-commit-file \
	checkpatch-base-commit-patch checkpatch-base-commit-file \
	checkpatch-all-files distclean
all: build copy_public copy_rootfs

build-libteec:
	@echo "Building libteec.so"
	@$(MAKE) --directory=libteec --no-print-directory

build-tee-supplicant: build-libteec
	@echo "Building tee-supplicant"
	$(MAKE) --directory=tee-supplicant  --no-print-directory

build: build-libteec build-tee-supplicant

install: build copy_public copy_rootfs

copy: copy_public copy_rootfs

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

EXPORT_DIR ?= $(O)/export

ifdef ROOTFS_DIR
copy_rootfs:
	cp ${O}/libteec/libteec.so* ${ROOTFS_DIR}/usr/lib
	cp ${O}/tee-supplicant/tee-supplicant ${ROOTFS_DIR}/usr/local/bin
else
copy_rootfs:
	@echo Rootfs copy cannot be done because ROOTFS_DIR is not defined
endif

copy_public:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include ${EXPORT_DIR}/bin
	cp ${O}/libteec/libteec.so* ${EXPORT_DIR}/lib
	cp ${O}/tee-supplicant/tee-supplicant ${EXPORT_DIR}/bin
	cp public/*.h ${EXPORT_DIR}/include
