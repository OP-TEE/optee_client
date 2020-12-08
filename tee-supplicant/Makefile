include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/tee-supplicant

# Emulate RPMB ioctl's by default
RPMB_EMU	?= 1

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
		   handle.c \
		   plugin.c


ifeq ($(CFG_GP_SOCKETS),y)
TEES_SRCS 	+= tee_socket.c
endif

ifeq ($(RPMB_EMU),1)
TEES_SRCS	+= sha2.c hmac_sha2.c
endif
ifneq (,$(filter y,$(CFG_TA_GPROF_SUPPORT) $(CFG_FTRACE_SUPPORT)))
TEES_SRCS	+= prof.c
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
		   -DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\" \
		   -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\" \
		   -DTEE_PLUGIN_LOAD_PATH=\"$(CFG_TEE_PLUGIN_LOAD_PATH)\"

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
TEES_LFLAGS    := $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec

ifeq ($(CFG_TA_GPROF_SUPPORT),y)
TEES_CFLAGS	+= -DCFG_TA_GPROF_SUPPORT
endif

ifeq ($(CFG_FTRACE_SUPPORT),y)
TEES_CFLAGS	+= -DCFG_FTRACE_SUPPORT
endif

TEES_LFLAGS	+= -lpthread
# Needed to get clock_gettime() for for glibc versions before 2.17
TEES_LFLAGS	+= -lrt
# Needed to dynamically load user plugins
TEES_LFLAGS	+= -ldl
# Needed for dlopen()
TEES_LFLAGS += -Wl,-rpath=$(CFG_TEE_PLUGIN_LOAD_PATH)

tee-supplicant: $(TEES_FILE)

$(TEES_FILE): $(TEES_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -o $@ $+ $(TEES_LFLAGS)
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
