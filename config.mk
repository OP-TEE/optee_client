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

# CFG_TEE_FS_PARENT_PATH
#   Path to folder that will contain TEE filesystem.
#   This folder can be created with the required permission in an init
#   script during boot, else it will be created by the tee-supplicant on
#   first REE FS access.
CFG_TEE_FS_PARENT_PATH ?= /data/tee

# CFG_TEE_CLIENT_LOG_FILE
#   The location of the client log file when logging to file is enabled.
CFG_TEE_CLIENT_LOG_FILE ?= $(CFG_TEE_FS_PARENT_PATH)/teec.log

# CFG_TEE_CLIENT_LOAD_PATH
#   The location of the client library file.
CFG_TEE_CLIENT_LOAD_PATH ?= /lib

# CFG_TEE_PLUGIN_LOAD_PATH
#   The location of the user plugins
CFG_TEE_PLUGIN_LOAD_PATH ?= /usr/lib/tee-supplicant/plugins/

# CFG_TA_TEST_PATH
#   Enable the tee test path.  When enabled, the supplicant will try
#   loading from a debug path before the regular path.  This allows test
#   such as 1008.5 that test loading of corrupt TAs.
CFG_TA_TEST_PATH ?= n

# CFG_GP_SOCKETS
#   Enable Global Platform Sockets support
CFG_GP_SOCKETS ?= y

# CFG_TA_GPROF_SUPPORT
#   Enable dumping gprof data, not used unless secure world decides
#   to dump something
CFG_TA_GPROF_SUPPORT ?= y

# CFG_FTRACE_SUPPORT
#   Enable dumping ftrace data, not used unless secure world decides
#   to dump something
CFG_FTRACE_SUPPORT ?= y

# Default output directory.
# May be absolute, or relative to the optee_client source directory.
O               ?= out

# To be used instead of $(O) in sub-directories
OO := $(if $(filter /%,$(O)),$(O),$(CURDIR)/../$(O))

#########################################################################
# Private Values                                                        #
#########################################################################

# Check that settings are coherent.

