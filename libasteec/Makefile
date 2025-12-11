include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libasteec

.PHONY: all libasteec clean

all: libasteec
install: libasteec

LIB_NAME	:= libasteec
MAJOR_VERSION	:= 1
MINOR_VERSION	:= 0
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBASTEEC_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBASTEEC_AR_LIBRARY	:= $(LIB_NAME).a

LIBASTEEC_SRC_DIR	:= src

LIBASTEEC_SRCS		= asteec.c

LIBASTEEC_INCLUDES	= ${CURDIR}/include
LIBASTEEC_INCLUDES 	+= ${CURDIR}/../libteec/include

LIBASTEEC_CFLAGS	:= $(addprefix -I, $(LIBASTEEC_INCLUDES)) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBASTEEC_LFLAGS	:= $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec

LIBASTEEC_OBJ_DIR	:= $(OUT_DIR)
LIBASTEEC_OBJS		:= $(patsubst %.c,$(LIBASTEEC_OBJ_DIR)/%.o, $(LIBASTEEC_SRCS))

$(LIBASTEEC_OBJ_DIR)/%.o: ${LIBASTEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBASTEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBASTEEC_CFLAGS) -c $< -o $@

libasteec: $(OUT_DIR)/$(LIBASTEEC_SO_LIBRARY)

$(OUT_DIR)/$(LIBASTEEC_SO_LIBRARY): $(LIBASTEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJOR) -o $@ $+ $(LIBASTEEC_LFLAGS)
	@echo ""

libasteec: $(OUT_DIR)/$(LIBASTEEC_AR_LIBRARY)

$(OUT_DIR)/$(LIBASTEEC_AR_LIBRARY): $(LIBASTEEC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libasteec:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBASTEEC_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBASTEEC_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBASTEEC_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))

