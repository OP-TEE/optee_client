include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libckteeaclc

.PHONY: all libckteeaclc clean

all: libckteeaclc
install: libckteeaclc

LIB_NAME	:= libckteeaclc
MAJOR_VERSION	:= 0
MINOR_VERSION	:= 1
PATCH_VERSION	:= 0

LIB_MAJOR		:= $(LIB_NAME).so.$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_PAT		:= $(LIB_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBCKTEEACLC_SO_LIBRARY	:= $(LIB_MAJ_MIN_PAT)
LIBCKTEEACLC_AR_LIBRARY	:= $(LIB_NAME).a

LIBCKTEEACLC_SRC_DIR	:= src

LIBCKTEEACLC_SRCS	= group.c

LIBCKTEEACLC_INCLUDES	= ${CURDIR}/include

LIBCKTEEACLC_CFLAGS	:= $(addprefix -I, $(LIBCKTEEACLC_INCLUDES)) \
			$(CFLAGS) -D_GNU_SOURCE -fPIC

LIBCKTEEACLC_LFLAGS	:= $(LDFLAGS)

LIBCKTEEACLC_OBJ_DIR	:= $(OUT_DIR)
LIBCKTEEACLC_OBJS	:= $(patsubst %.c,$(LIBCKTEEACLC_OBJ_DIR)/%.o, $(LIBCKTEEACLC_SRCS))

$(LIBCKTEEACLC_OBJ_DIR)/%.o: ${LIBCKTEEACLC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(LIBCKTEEACLC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(LIBCKTEEACLC_CFLAGS) -c $< -o $@

libckteeaclc: $(OUT_DIR)/$(LIBCKTEEACLC_SO_LIBRARY)

$(OUT_DIR)/$(LIBCKTEEACLC_SO_LIBRARY): $(LIBCKTEEACLC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIBCKTEEACLC_SO_LIBRARY) -o $@ $+ $(LIBCKTEEACLC_LFLAGS)
	@echo ""

libckteeaclc: $(OUT_DIR)/$(LIBCKTEEACLC_AR_LIBRARY)

$(OUT_DIR)/$(LIBCKTEEACLC_AR_LIBRARY): $(LIBCKTEEACLC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

libckteeaclc:
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_PAT) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME).so

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(LIBCKTEEACLC_OBJS)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN_PAT)
	$(RM) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(RM) $(OUT_DIR)/$(LIB_MAJOR)
	$(RM) $(OUT_DIR)/$(LIBCKTEEACLC_SO_LIBRARY)
	$(RM) $(OUT_DIR)/$(LIBCKTEEACLC_AR_LIBRARY)
	$(call rmdir,$(OUT_DIR))