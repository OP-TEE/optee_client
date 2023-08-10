################################################################################
# Android optee-client, libckteec and optee-supplicant makefile                #
################################################################################
LOCAL_PATH := $(call my-dir)

# 3 (debug) is too noisy
CFG_TEE_CLIENT_LOG_LEVEL ?= 2
CFG_TEE_SUPP_LOG_LEVEL ?= 2

# Define Android-specific configuration before including config.mk
CFG_TEE_CLIENT_LOAD_PATH ?= /vendor/lib
TEEC_TEST_LOAD_PATH ?= /data/vendor/tee
CFG_TEE_FS_PARENT_PATH ?= /data/vendor/tee
CFG_TEE_SUPP_PLUGINS ?= y
ifneq ($(strip $($(combo_2nd_arch_prefix)TARGET_TOOLS_PREFIX)),)
CFG_TEE_PLUGIN_LOAD_PATH ?= /vendor/lib64/tee-supplicant/plugins/
else
CFG_TEE_PLUGIN_LOAD_PATH ?= /vendor/lib/tee-supplicant/plugins/
endif

$(info CFG_TEE_PLUGIN_LOAD_PATH = ${CFG_TEE_PLUGIN_LOAD_PATH})


################################################################################
# Include optee-client common config and flags                                 #
################################################################################
include $(LOCAL_PATH)/config.mk
include $(LOCAL_PATH)/android_flags.mk

optee_CFLAGS = $(CFLAGS)

################################################################################
# Build libteec.so - TEE (Trusted Execution Environment) shared library        #
################################################################################
include $(CLEAR_VARS)
LOCAL_CFLAGS += $(optee_CFLAGS)

ifneq ($(CFG_TEE_CLIENT_LOG_FILE),)
LOCAL_CFLAGS += -DTEEC_LOG_FILE=\"$(CFG_TEE_CLIENT_LOG_FILE)\"
endif

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL)
LOCAL_CFLAGS += -DBINARY_PREFIX=\"TEEC\"

LOCAL_SRC_FILES := libteec/src/tee_client_api.c \
                   libteec/src/teec_trace.c
ifeq ($(CFG_TEE_BENCHMARK),y)
LOCAL_CFLAGS += -DCFG_TEE_BENCHMARK
LOCAL_SRC_FILES += teec_benchmark.c
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/libteec/include

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libteec

LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

# Build the 32-bit and 64-bit versions.
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/libteec/include

include $(BUILD_SHARED_LIBRARY)

################################################################################
# Build libckteec.so                                                           #
################################################################################
include $(CLEAR_VARS)

LOCAL_CFLAGS += $(optee_CFLAGS)

LOCAL_SRC_FILES := libckteec/src/pkcs11_api.c \
                   libckteec/src/ck_debug.c \
                   libckteec/src/ck_helpers.c \
                   libckteec/src/invoke_ta.c \
                   libckteec/src/pkcs11_processing.c \
                   libckteec/src/pkcs11_token.c \
                   libckteec/src/serializer.c \
                   libckteec/src/serialize_ck.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/libteec/include \
                    $(LOCAL_PATH)/libckteec/include

LOCAL_SHARED_LIBRARIES := libteec

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libckteec

LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

# Build the 32-bit and 64-bit versions.
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/libckteec/include

include $(BUILD_SHARED_LIBRARY)

################################################################################
# Build TEE Supplicant                                                         #
################################################################################
include $(LOCAL_PATH)/tee-supplicant/tee_supplicant_android.mk
