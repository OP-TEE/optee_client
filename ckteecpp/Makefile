include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/ckteecpp

.PHONY: all ckteecpp

all: ckteecpp

MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0
MAJ_MIN_P	:= $(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)

# Write version to file so that it can be used for up-to-date checks
MAJ_MIN_P_FILE	:= $(OUT_DIR)/metadata/version
$(shell mkdir -p $(dir $(MAJ_MIN_P_FILE)); echo $(MAJ_MIN_P) | \
	diff $(MAJ_MIN_P_FILE) - > /dev/null || \
	echo $(MAJ_MIN_P) > $(MAJ_MIN_P_FILE) )

CKTEECPP_PKGCONF	:= $(OO)/pkgconfig/ckteecpp.pc

ckteecpp: $(CKTEECPP_PKGCONF)

$(CKTEECPP_PKGCONF): ${CURDIR}/ckteecpp.pc.in $(MAJ_MIN_P_FILE) $(OO)/pkgconfig
	sed 's/@PROJECT_VERSION@/${MAJ_MIN_P}/g' ${CURDIR}/ckteecpp.pc.in > $(CKTEECPP_PKGCONF)

$(OO)/pkgconfig:
	mkdir -p $(OO)/pkgconfig