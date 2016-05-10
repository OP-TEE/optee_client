################################################################################
# Android optee-client and optee-supplicant makefile                                                #
################################################################################
LOCAL_PATH := $(call my-dir)

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

ifeq ($(CFG_TEE_CLIENT_LOG_FILE), true)
LOCAL_CFLAGS += -DTEEC_LOG_FILE=$(CFG_TEE_CLIENT_LOG_FILE)
endif

LOCAL_CFLAGS += -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL)
LOCAL_CFLAGS += -DBINARY_PREFIX=\"TEEC\"

LOCAL_SRC_FILES := libteec/src/tee_client_api.c\
                  libteec/src/teec_trace.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/public \
                    $(LOCAL_PATH)/libteec/include \

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libteec
LOCAL_MODULE_TAGS := optional

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/public

include $(BUILD_SHARED_LIBRARY)

ifeq ($(CFG_SQL_FS),y)

#
# Build libsqlite3.a
#
include $(CLEAR_VARS)
LOCAL_MODULE := libsqlite3
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := libsqlite3/src/sqlite3.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libsqlite3/include
libsqlite3_CFLAGS_REMOVE := -Wall -Wbad-function-cast -Wswitch-default \
                            -Wfloat-equal -Werror -Wwrite-strings -Wcast-align
LOCAL_CFLAGS += $(filter-out $(libsqlite3_CFLAGS_REMOVE),$(optee_CFLAGS))
include $(BUILD_STATIC_LIBRARY)

#
# Build libsqlfs.so
#
include $(CLEAR_VARS)
LOCAL_MODULE := libsqlfs
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := libsqlfs/src/sqlfs.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libsqlfs/include \
                    $(LOCAL_PATH)/libsqlite3/include
libsqlfs_CFLAGS_REMOVE := -Wall -Wunused-parameter -Wmissing-prototypes \
                          -Wdiscarded-qualifiers \
                          -Wmissing-declarations \
                          -Wwrite-strings -Wstrict-prototypes
LOCAL_CFLAGS += $(filter-out $(libsqlfs_CFLAGS_REMOVE),$(optee_CFLAGS)) \
                -Wno-missing-format-attribute
LOCAL_STATIC_LIBRARIES := libsqlite3
LOCAL_LDLIBS := -llog
# Note: building a shared library (.so) here, because statically
# linking a LGPL library has licensing implications. Make sure you review
# and comply with libsqlfs/COPYING section 6 before doing so.
include $(BUILD_SHARED_LIBRARY)

endif # CFG_SQL_FS == y

# TEE Supplicant
include $(LOCAL_PATH)/tee-supplicant/tee_supplicant_android.mk
