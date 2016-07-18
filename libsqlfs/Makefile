# !! Please note: !!
#
# The license for libsqlfs is LGPLv2, so be careful about changing the code
# and/or linking it statically! See COPYING section 6.

include ../flags.mk

O ?= out
OUT_DIR	?= ${CURDIR}/../$(O)/libsqlfs

.PHONY: all libsqlfs clean

all: libsqlfs
################################################################################
# SQLFS configuration
################################################################################
MAJOR_VERSION := 1
MINOR_VERSION := 0
# Note: building a shared library (.so) here, because statically
# linking a LGPL library has licensing implications. Make sure you review
# and comply with libsqlfs/COPYING section 6 before doing so.
LIB_NAME := libsqlfs.so
LIB_MAJOR := $(LIB_NAME).$(MAJOR_VERSION)
LIB_MAJ_MIN := $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION)

SQLFS_SRCS := sqlfs.c

SQLFS_SRC_DIR := src
SQLFS_OBJ_DIR := $(OUT_DIR)
SQLFS_OBJS := $(patsubst %.c,$(SQLFS_OBJ_DIR)/%.o, $(SQLFS_SRCS))
SQLFS_INCLUDES := $(CURDIR)/include $(CURDIR)/../libsqlite3/include

SQLFS_CFLAGS_REMOVE := -Wall -Wunused-parameter \
        -Wmissing-prototypes -Wdiscarded-qualifiers \
        -Wunused-variable -Wmissing-declarations \
	-Wwrite-strings -Wstrict-prototypes
SQLFS_CFLAGS := $(addprefix -I, $(SQLFS_INCLUDES)) \
	$(filter-out $(SQLFS_CFLAGS_REMOVE),$(CFLAGS)) \
	-Wno-missing-format-attribute

SQLFS_LFLAGS := -lpthread
SQLFS_LIBS := $(CURDIR)/../$(O)/libsqlite3/libsqlite3.a
SQLFS_LIBRARY := $(OUT_DIR)/$(LIB_MAJ_MIN)

libsqlfs: $(SQLFS_LIBRARY)
	$(VPREFIX)ln -sf $(SQLFS_LIBRARY) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(OUT_DIR)/$(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME)

$(SQLFS_LIBRARY): $(SQLFS_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJ_MIN) $(SQLFS_LFLAGS) -o $@ $+ $(SQLFS_LIBS)
	@echo ""

$(SQLFS_OBJ_DIR)/%.o: ${SQLFS_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(SQLFS_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(SQLFS_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(OUT_DIR)
