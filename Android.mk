################################################################################
# Android optee-client and optee-supplicant makefile                                                #
################################################################################
LOCAL_PATH := $(call my-dir)

################################################################################
# Include optee-client common config and flags                                 #
################################################################################
include $(LOCAL_PATH)/config.mk
include $(LOCAL_PATH)/flags.mk

################################################################################
# Build libteec.so - TEE (Trusted Execution Environment) shared library        #
################################################################################
include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += $(CFLAGS)

ifeq ($(CFG_TEE_CLIENT_LOG_FILE), true)
LOCAL_CFLAGS += -DTEEC_LOG_FILE=$(CFG_TEE_CLIENT_LOG_FILE)
endif

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL)
LOCAL_CFLAGS += -DBINARY_PREFIX=\"TEEC\"

LOCAL_SRC_FILES += libteec/src/tee_client_api.c
LOCAL_SRC_FILES += libteec/src/teec_trace.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/public \
		$(LOCAL_PATH)/libteec/include \

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libteec
LOCAL_MODULE_TAGS := optional
include $(BUILD_SHARED_LIBRARY)

################################################################################
# Build tee supplicant                                                         #
################################################################################
include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += $(CFLAGS)

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL)
LOCAL_CFLAGS += -DBINARY_PREFIX=\"TEES\"
LOCAL_CFLAGS += -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\"

LOCAL_SRC_FILES += tee-supplicant/src/handle.c
LOCAL_SRC_FILES += tee-supplicant/src/tee_supp_fs.c
LOCAL_SRC_FILES	+= tee-supplicant/src/tee_supplicant.c
LOCAL_SRC_FILES	+= tee-supplicant/src/teec_ta_load.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/public \
		$(LOCAL_PATH)/libteec/include \
		$(LOCAL_PATH)/tee-supplicant/src

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := tee_supplicant
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
