project (tee-supplicant C)

################################################################################
# Configuration flags always included
################################################################################
option (CFG_TA_TEST_PATH "Enable tee-supplicant to load from test/debug path" ON)
option (RPMB_EMU "Enable tee-supplicant to emulate RPMB" ON)
option (CFG_TA_GPROF_SUPPORT "Enabled tee-supplicant profiling support" OFF)

set (CFG_TEE_SUPP_LOG_LEVEL "1" CACHE STRING "tee-supplicant log level")
# FIXME: Question is, is this really needed? Should just use defaults from # GNUInstallDirs?
set (CFG_TEE_CLIENT_LOAD_PATH "/lib" CACHE STRING "Location of libteec.so")
set (CFG_TEE_FS_PARENT_PATH "/data" CACHE STRING "Location of TEE filesystem (secure storage)")
# FIXME: Why do we have if defined(CFG_GP_SOCKETS) && CFG_GP_SOCKETS == 1 in the c-file?
set (CFG_GP_SOCKETS "1" CACHE STRING "Enable GlobalPlatform Socket API support")

################################################################################
# Source files
################################################################################
set (SRC
	src/handle.c
	src/hmac_sha2.c
	src/rpmb.c
	src/sha2.c
	src/tee_supp_fs.c
	src/tee_supplicant.c
	src/teec_ta_load.c
)

if (CFG_GP_SOCKETS)
	set (SRC ${SRC} src/tee_socket.c)
endif()

if (CFG_TA_GPROF_SUPPORT)
	set (SRC ${SRC} src/gprof.c)
endif()

################################################################################
# Built binary
################################################################################
add_executable (${PROJECT_NAME} ${SRC})

################################################################################
# Flags always set
################################################################################
target_compile_definitions (${PROJECT_NAME}
	PRIVATE -DCFG_TEE_SUPP_LOG_LEVEL=${CFG_TEE_SUPP_LOG_LEVEL}
	PRIVATE -DTEEC_LOAD_PATH="${CFG_TEE_CLIENT_LOAD_PATH}"
	PRIVATE -DTEE_FS_PARENT_PATH="${CFG_TEE_FS_PARENT_PATH}"
	PRIVATE -DBINARY_PREFIX="TSUP"
)

################################################################################
# Optional flags
################################################################################
if (CFG_GP_SOCKETS)
	target_compile_definitions (${PROJECT_NAME}
		PRIVATE -DCFG_GP_SOCKETS=${CFG_GP_SOCKETS})
endif()

if (CFG_TA_TEST_PATH)
	target_compile_definitions (${PROJECT_NAME}
		PRIVATE -DCFG_TA_TEST_PATH=${CFG_TA_TEST_PATH})
endif()

if (CFG_TA_TEST_PATH)
	target_compile_definitions (${PROJECT_NAME}
		PRIVATE -DRPMB_EMU=1)
endif()

if (CFG_TA_GPROF_SUPPORT)
	target_compile_definitions (${PROJECT_NAME}
		PRIVATE -DCFG_TA_GPROF_SUPPORT)
endif()

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries (${PROJECT_NAME}
	PRIVATE teec
	PRIVATE optee-client-headers)

################################################################################
# Install targets
################################################################################
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_SBINDIR})
