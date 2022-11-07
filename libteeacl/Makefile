include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libteeacl

.PHONY: all libteeacl check-libuuid clean

all: libteeacl
install: libteeacl

LIB_NAME	:= libteeacl
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT	:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBTEEACL_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBTEEACL_AR_LIBRARY	:= $(LIB_NAME).a

LIBTEEACL_SRC_DIR	:= src

LIBTEEACL_SRCS	= group.c
LIBTEEACL_SRCS	+= tee_uuid.c

LIBTEEACL_INCLUDES	= ${CURDIR}/include

LIBTEEACL_CFLAGS	:= $(addprefix -I, $(LIBTEEACL_INCLUDES)) \
			$(shell $(PKG_CONFIG) --cflags uuid) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBTEEACL_LFLAGS	:= $(LDFLAGS) $(shell $(PKG_CONFIG) --libs uuid)

LIBTEEACL_OBJ_DIR	:= $(OUT_DIR)
LIBTEEACL_OBJS	:= $(patsubst %.c,$(LIBTEEACL_OBJ_DIR)/%.o, $(LIBTEEACL_SRCS))

$(LIBTEEACL_OBJ_DIR)/%.o: ${LIBTEEACL_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBTEEACL_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBTEEACL_CFLAGS) -c $< -o $@

libteeacl: check-libuuid

check-libuuid:
	@echo "  Finding uuid.pc"
	$(VPREFIX)$(PKG_CONFIG) --atleast-version=2.34 uuid

libteeacl: $(OUT_DIR)/$(LIBTEEACL_SO_LIBRARY)

$(OUT_DIR)/$(LIBTEEACL_SO_LIBRARY): $(LIBTEEACL_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIBTEEACL_SO_LIBRARY) -o $@ $+ $(LIBTEEACL_LFLAGS)
	@echo ""

libteeacl: $(OUT_DIR)/$(LIBTEEACL_AR_LIBRARY)

$(OUT_DIR)/$(LIBTEEACL_AR_LIBRARY): $(LIBTEEACL_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libteeacl:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBTEEACL_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBTEEACL_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBTEEACL_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))
