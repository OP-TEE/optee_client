include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libseteec

.PHONY: all libseteec clean

all: libseteec
install: libseteec

LIB_NAME	:= libseteec
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBSETEEC_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBSETEEC_AR_LIBRARY	:= $(LIB_NAME).a

LIBSETEEC_SRC_DIR	:= src

LIBSETEEC_SRCS	= se.c

LIBSETEEC_INCLUDES	= ${CURDIR}/include
LIBSETEEC_INCLUDES 	+= ${CURDIR}/../libteec/include

LIBSETEEC_CFLAGS	:= $(addprefix -I, $(LIBSETEEC_INCLUDES)) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBSETEEC_LFLAGS	:= $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec -lpthread

LIBSETEEC_OBJ_DIR	:= $(OUT_DIR)
LIBSETEEC_OBJS		:= $(patsubst %.c,$(LIBSETEEC_OBJ_DIR)/%.o, $(LIBSETEEC_SRCS))

$(LIBSETEEC_OBJ_DIR)/%.o: ${LIBSETEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBSETEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBSETEEC_CFLAGS) -c $< -o $@

libseteec: $(OUT_DIR)/$(LIBSETEEC_SO_LIBRARY)

$(OUT_DIR)/$(LIBSETEEC_SO_LIBRARY): $(LIBSETEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJOR) -o $@ $+ $(LIBSETEEC_LFLAGS)
	@echo ""

libseteec: $(OUT_DIR)/$(LIBSETEEC_AR_LIBRARY)

$(OUT_DIR)/$(LIBSETEEC_AR_LIBRARY): $(LIBSETEEC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libseteec:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBSETEEC_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBSETEEC_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBSETEEC_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))

