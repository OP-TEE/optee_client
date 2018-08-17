#########################################################################
# Public variables                                                      #
# Developers may override these values when calling the makefile,       #
# as for example                                                        #
#       CFG_TEE_CLIENT_LOG_LEVEL=1 make                                 #
# Note:                                                                 #
#   Please do not use export to declare the variables, so that to avoid #
#   compiling problem for android platform                              #
#########################################################################

# CFG_TEE_CLIENT_LOG_LEVEL
#   Client (User Non Secure) log level
#   Supported values: 0 (no traces) to 4 (all traces)
CFG_TEE_CLIENT_LOG_LEVEL?=1

# CFG_TEE_SUPP_LOG_LEVEL
#   Supplicant log level
#   Supported values: 0 (no traces) to 4 (all traces)
CFG_TEE_SUPP_LOG_LEVEL?=1

# CFG_TEE_DATA_PATH
#   Specify the root path for the TEE data directory.
CFG_TEE_DATA_PATH ?= /data/vendor/tee

# CFG_TEE_LOGS_PATH
#   Specify the root path for the TEE logs directory.
#   Normally it will be the logs directory under $(CFG_TEE_DATA_PATH)
CFG_TEE_LOGS_PATH ?= $(CFG_TEE_DATA_PATH)/logs

# CFG_TEE_CLIENT_LOG_FILE
# The location of the client log file when logging to file is enabled.
CFG_TEE_CLIENT_LOG_FILE ?= $(CFG_TEE_LOGS_PATH)/teec.log

# CFG_TEE_CLIENT_LOAD_PATH
# The location of the client library file.
CFG_TEE_CLIENT_LOAD_PATH ?= /lib

# CFG_TEE_FS_PARENT_PATH
# Path to folder that will contain TEE filesystem.
# This folder should be created before tee-supplicant start.
CFG_TEE_FS_PARENT_PATH ?= /data

# CFG_TA_TEST_PATH
# Enable the tee test path.  When enabled, the supplicant will try
# loading from a debug path before the regular path.  This allows test
# such as 1008.5 that test loading of corrupt TAs.
CFG_TA_TEST_PATH ?= y

# CFG_GP_SOCKETS
# Enable Global Platform Sockets support
CFG_GP_SOCKETS ?= y

# Default output directory.
# May be absolute, or relative to the optee_client source directory.
O               ?= out

# To be used instead of $(O) in sub-directories
OO := $(if $(filter /%,$(O)),$(O),$(CURDIR)/../$(O))

#########################################################################
# Private Values                                                        #
#########################################################################

# Check that settings are coherent.

ifdef ARM_TOOLCHAIN_DIR
ifeq ($(wildcard ${ARM_TOOLCHAIN_DIR}/bin/${ARM_GCC_PREFIX}-gcc),)
  $(error "ARM_TOOLCHAIN_DIR wrongly setup. Is ${ARM_TOOLCHAIN_DIR}")
endif
endif

