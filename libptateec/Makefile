include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libptateec

.PHONY: all libptateec clean

all: libptateec
install: libptateec

LIB_NAME	:= libptateec
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBPTATEEC_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBPTATEEC_AR_LIBRARY	:= $(LIB_NAME).a

LIBPTATEEC_SRC_DIR	:= src

LIBPTATEEC_SRCS	= pta.c \
		  pta_imx_manufacturing_protection.c

LIBPTATEEC_INCLUDES	= ${CURDIR}/include
LIBPTATEEC_INCLUDES 	+= ${CURDIR}/../public

LIBPTATEEC_CFLAGS	:= $(addprefix -I, $(LIBPTATEEC_INCLUDES)) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBPTATEEC_LFLAGS	:= $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec -lpthread

LIBPTATEEC_OBJ_DIR	:= $(OUT_DIR)
LIBPTATEEC_OBJS		:= $(patsubst %.c,$(LIBPTATEEC_OBJ_DIR)/%.o, $(LIBPTATEEC_SRCS))

$(LIBPTATEEC_OBJ_DIR)/%.o: ${LIBPTATEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBPTATEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBPTATEEC_CFLAGS) -c $< -o $@

libptateec: $(OUT_DIR)/$(LIBPTATEEC_SO_LIBRARY)

$(OUT_DIR)/$(LIBPTATEEC_SO_LIBRARY): $(LIBPTATEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJOR) -o $@ $+ $(LIBPTATEEC_LFLAGS)
	@echo ""

libptateec: $(OUT_DIR)/$(LIBPTATEEC_AR_LIBRARY)

$(OUT_DIR)/$(LIBPTATEEC_AR_LIBRARY): $(LIBPTATEEC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libptateec:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBPTATEEC_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBPTATEEC_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBPTATEEC_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))
