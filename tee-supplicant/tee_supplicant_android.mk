################################################################################
# Build tee supplicant                                                         #
################################################################################
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += $(optee_CFLAGS)

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
                -DBINARY_PREFIX=\"TEES\" \
                -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\" \
		-DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\"

ifneq ($(TEEC_TEST_LOAD_PATH),)
LOCAL_CFLAGS += -DTEEC_TEST_LOAD_PATH=\"$(TEEC_TEST_LOAD_PATH)\"
endif

ifeq ($(CFG_TA_TEST_PATH),y)
LOCAL_CFLAGS += -DCFG_TA_TEST_PATH=1
endif

ifeq ($(CFG_GP_SOCKETS),y)
LOCAL_CFLAGS += -DCFG_GP_SOCKETS=1
endif

LOCAL_SRC_FILES += src/handle.c \
                   src/tee_supp_fs.c \
                   src/tee_supplicant.c \
                   src/teec_ta_load.c \
                   src/rpmb.c

ifeq ($(CFG_GP_SOCKETS),y)
LOCAL_SRC_FILES += src/tee_socket.c
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../public \
    $(LOCAL_PATH)/../libteec/include \
    $(LOCAL_PATH)/src

LOCAL_SHARED_LIBRARIES := libteec

ifeq ($(CFG_TA_GPROF_SUPPORT),y)
LOCAL_SRC_FILES += src/gprof.c
LOCAL_CFLAGS += -DCFG_TA_GPROF_SUPPORT
endif

LOCAL_MODULE := tee-supplicant
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true
include $(BUILD_EXECUTABLE)
