include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libckteec

.PHONY: all libckteec clean

all: libckteec
install: libckteec

LIB_NAME	:= libckteec
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBCKTEEC_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBCKTEEC_AR_LIBRARY	:= $(LIB_NAME).a

LIBCKTEEC_SRC_DIR	:= src

LIBCKTEEC_SRCS		= pkcs11_api.c
LIBCKTEEC_SRCS		+= ck_debug.c
LIBCKTEEC_SRCS		+= ck_helpers.c
LIBCKTEEC_SRCS		+= invoke_ta.c
LIBCKTEEC_SRCS		+= pkcs11_processing.c
LIBCKTEEC_SRCS		+= pkcs11_token.c
LIBCKTEEC_SRCS		+= serializer.c
LIBCKTEEC_SRCS		+= serialize_ck.c

LIBCKTEEC_INCLUDES	= ${CURDIR}/include
LIBCKTEEC_INCLUDES 	+= ${CURDIR}/../public

LIBCKTEEC_CFLAGS	:= $(addprefix -I, $(LIBCKTEEC_INCLUDES)) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBCKTEEC_LFLAGS	:= $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec

LIBCKTEEC_OBJ_DIR	:= $(OUT_DIR)
LIBCKTEEC_OBJS		:= $(patsubst %.c,$(LIBCKTEEC_OBJ_DIR)/%.o, $(LIBCKTEEC_SRCS))

$(LIBCKTEEC_OBJ_DIR)/%.o: ${LIBCKTEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBCKTEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBCKTEEC_CFLAGS) -c $< -o $@

libckteec: $(OUT_DIR)/$(LIBCKTEEC_SO_LIBRARY)

$(OUT_DIR)/$(LIBCKTEEC_SO_LIBRARY): $(LIBCKTEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJOR) -o $@ $+ $(LIBCKTEEC_LFLAGS)
	@echo ""

libckteec: $(OUT_DIR)/$(LIBCKTEEC_AR_LIBRARY)

$(OUT_DIR)/$(LIBCKTEEC_AR_LIBRARY): $(LIBCKTEEC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libckteec:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBCKTEEC_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBCKTEEC_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBCKTEEC_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))

