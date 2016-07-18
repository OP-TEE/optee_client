include ../flags.mk
include ../config.mk

OUT_DIR		?= ${CURDIR}/../$(O)/tee-supplicant

# Emulate RPMB ioctl's
RPMB_EMU	:= 1

.PHONY: all tee-supplicant clean

all: tee-supplicant
################################################################################
# Teec configuration
################################################################################
PACKAGE_NAME	:= tee-supplicant

TEES_SRCS	:= tee_supplicant.c \
		   teec_ta_load.c \
		   tee_supp_fs.c \
		   rpmb.c \
		   handle.c

ifeq ($(RPMB_EMU),1)
TEES_SRCS	+= sha2.c hmac_sha2.c
endif
ifeq ($(CFG_SQL_FS),y)
TEES_SRCS	+= sql_fs.c
endif

TEES_SRC_DIR	:= src
TEES_OBJ_DIR	:= $(OUT_DIR)
TEES_OBJS 	:= $(patsubst %.c,$(TEES_OBJ_DIR)/%.o, $(TEES_SRCS))
TEES_INCLUDES 	:= ${CURDIR}/../libteec/include \
		   ${CURDIR}/../libsqlite3/include \
		   ${CURDIR}/../libsqlfs/include \
		   ${CURDIR}/src \
		   ${CURDIR}/../public \

TEES_CFLAGS	:= $(addprefix -I, $(TEES_INCLUDES)) $(CFLAGS) \
		   -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"TEES\"
ifeq ($(RPMB_EMU),1)
TEES_CFLAGS	+= -DRPMB_EMU=1
endif
ifeq ($(CFG_TA_TEST_PATH),1)
TEES_CFLAGS	+= -DCFG_TA_TEST_PATH=1
endif
TEES_FILE	:= $(OUT_DIR)/$(PACKAGE_NAME)
TEES_LDFLAGS    := -L$(OUT_DIR)/../libteec -lteec

ifeq ($(CFG_SQL_FS),y)
TEES_CFLAGS	+= -DCFG_SQL_FS
TEES_CFLAGS	+= -Wno-strict-prototypes -Wno-implicit-function-declaration \
		   -Wno-nested-externs -Wno-unused-function
# Note: explicitly requesting a shared library (.so) here, because statically
# linking a LGPL library has licensing implications. Make sure you review
# and comply with libsqlfs/COPYING section 6 before doing so.
TEES_LDFLAGS	+= -L$(OUT_DIR)/../libsqlfs -l:libsqlfs.so -ldl
endif

TEES_LDFLAGS	+= -lpthread

tee-supplicant: $(TEES_FILE)

$(TEES_FILE): $(TEES_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -o $@ $+ $(TEES_LDFLAGS)
	@echo ""

$(TEES_OBJ_DIR)/%.o: $(TEES_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEES_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(OUT_DIR)
