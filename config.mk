#########################################################################
# Public variables                                                      #
# Developers may override these values when calling the makefile,       #
# as for example                                                        #
#       CFG_TEE_CLIENT_LOG_LEVEL=1 make                                 #
# or by declaring the variable in their environement, as for example    #
#       export CFG_TEE_CLIENT_LOG_LEVEL=1                               #
#       make                                                            #
#########################################################################

# CFG_TEE_CLIENT_LOG_LEVEL
#   Client (User Non Secure) log level
#   Supported values: 0 (no traces) to 4 (all traces)
CFG_TEE_CLIENT_LOG_LEVEL?=1
export CFG_TEE_CLIENT_LOG_LEVEL

# CFG_TEE_SUPP_LOG_LEVEL
#   Supplicant log level
#   Supported values: 0 (no traces) to 4 (all traces)
CFG_TEE_SUPP_LOG_LEVEL?=1
export CFG_TEE_SUPP_LOG_LEVEL

# CFG_TEE_CLIENT_LOG_FILE
# The location of the client log file when logging to file is enabled.
CFG_TEE_CLIENT_LOG_FILE ?= \"/data/teec.log\"

# CFG_TEE_SUPP_LOG_FILE
# The location of the supplicant log file when logging to file is enabled.
CFG_TEE_SUPP_LOG_FILE ?= \"/data/teesupp.log\"

# CFG_TEE_CLIENT_LOAD_PATH
# The location of the client library file.
CFG_TEE_CLIENT_LOAD_PATH ?= /system/lib

# Default out dir.
# Must be a relative path with respect to the op-tee-client root directory
O               ?= out
export O

#########################################################################
# Private Values                                                        #
#########################################################################

# Check that settings are coherent.

ifdef ARM_TOOLCHAIN_DIR
ifeq ($(wildcard ${ARM_TOOLCHAIN_DIR}/bin/${ARM_GCC_PREFIX}-gcc),)
  $(error "ARM_TOOLCHAIN_DIR wrongly setup. Is ${ARM_TOOLCHAIN_DIR}")
endif
export ARM_TOOLCHAIN_DIR
export ARM_GCC_PREFIX
endif

