################################################################################
# Build tee supplicant                                                         #
################################################################################
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS += $(optee_CFLAGS)

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL) \
                -DBINARY_PREFIX=\"TEES\" \
                -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\" \

LOCAL_SRC_FILES += src/handle.c \
                   src/tee_supp_fs.c \
                   src/tee_supplicant.c \
                   src/teec_ta_load.c \
                   src/rpmb.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../public \
    $(LOCAL_PATH)/../libteec/include \
    $(LOCAL_PATH)/src

LOCAL_SHARED_LIBRARIES := libteec \
                          libcutils
LOCAL_MODULE := tee-supplicant
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
