include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libsks

.PHONY: all libsks clean

all: libsks
install: libsks

LIB_NAME	:= libsks
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIBSKS_SO_LIBRARY	:= $(LIB_MAJ_MIN)
LIBSKS_AR_LIBRARY	:= $(LIB_NAME).a

LIBSKS_SRC_DIR		:= src

LIBSKS_SRCS		= pkcs11_api.c

LIBSKS_INCLUDES		= ${CURDIR}/include
LIBSKS_INCLUDES 	+= ${CURDIR}/../public

LIBSKS_CFLAGS		:= $(addprefix -I, $(LIBSKS_INCLUDES)) \
				$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBSKS_OBJ_DIR		:= $(OUT_DIR)
LIBSKS_OBJS		:= $(patsubst %.c,$(LIBSKS_OBJ_DIR)/%.o, $(LIBSKS_SRCS))

$(LIBSKS_OBJ_DIR)/%.o: ${LIBSKS_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBSKS_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBSKS_CFLAGS) -c $< -o $@

libsks: $(OUT_DIR)/$(LIBSKS_SO_LIBRARY)

$(OUT_DIR)/$(LIBSKS_SO_LIBRARY): $(LIBSKS_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIBSKS_SO_LIBRARY) $(LIBSKS_LFLAGS) -o $@ $+
	@echo ""

libsks: $(OUT_DIR)/$(LIBSKS_AR_LIBRARY)

$(OUT_DIR)/$(LIBSKS_AR_LIBRARY): $(LIBSKS_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libsks:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBSKS_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBSKS_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBSKS_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))

