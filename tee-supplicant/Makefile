include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/tee-supplicant

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


ifeq ($(CFG_GP_SOCKETS),y)
TEES_SRCS 	+= tee_socket.c
endif

ifeq ($(RPMB_EMU),1)
TEES_SRCS	+= sha2.c hmac_sha2.c
endif
ifeq ($(CFG_TA_GPROF_SUPPORT),y)
TEES_SRCS	+= gprof.c
endif

TEES_SRC_DIR	:= src
TEES_OBJ_DIR	:= $(OUT_DIR)
TEES_OBJS 	:= $(patsubst %.c,$(TEES_OBJ_DIR)/%.o, $(TEES_SRCS))
TEES_INCLUDES 	:= ${CURDIR}/../libteec/include \
		   ${CURDIR}/src \
		   ${CURDIR}/../public \

TEES_CFLAGS	:= $(addprefix -I, $(TEES_INCLUDES)) $(CFLAGS) \
		   -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"TEES\" \
		   -DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\"

ifeq ($(CFG_GP_SOCKETS),y)
TEES_CFLAGS	+= -DCFG_GP_SOCKETS=1
endif
ifeq ($(RPMB_EMU),1)
TEES_CFLAGS	+= -DRPMB_EMU=1
endif
ifeq ($(CFG_TA_TEST_PATH),y)
TEES_CFLAGS	+= -DCFG_TA_TEST_PATH=1
endif
TEES_FILE	:= $(OUT_DIR)/$(PACKAGE_NAME)
TEES_LDFLAGS    := -L$(OUT_DIR)/../libteec -lteec

ifeq ($(CFG_TA_GPROF_SUPPORT),y)
TEES_CFLAGS	+= -DCFG_TA_GPROF_SUPPORT
endif

TEES_LDFLAGS	+= -lpthread
# Needed to get clock_gettime() for for glibc versions before 2.17
TEES_LDFLAGS	+= -lrt

tee-supplicant: $(TEES_FILE)

$(TEES_FILE): $(TEES_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -o $@ $+ $(TEES_LDFLAGS)
	@echo ""

$(TEES_OBJ_DIR)/%.o: $(TEES_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEES_CFLAGS) $(TEES_CFLAGS_$(notdir $<)) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(TEES_OBJS) $(TEES_FILE)
	$(call rmdir,$(OUT_DIR))
