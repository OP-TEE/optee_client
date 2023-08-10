project(tee-supplicant C)

################################################################################
# Configuration flags always included
################################################################################
option(CFG_TA_TEST_PATH "Enable tee-supplicant to load from test/debug path" OFF)
option(RPMB_EMU "Enable tee-supplicant to emulate RPMB" ON)
option(CFG_TA_GPROF_SUPPORT "Enable tee-supplicant support for TAs instrumented with gprof" ON)
option(CFG_FTRACE_SUPPORT "Enable tee-supplicant support for TAs instrumented with ftrace" ON)
option(CFG_TEE_SUPP_PLUGINS "Enable tee-supplicant plugin support" ON)

set(CFG_TEE_SUPP_LOG_LEVEL "1" CACHE STRING "tee-supplicant log level")
# FIXME: Question is, is this really needed? Should just use defaults from # GNUInstallDirs?
set(CFG_TEE_CLIENT_LOAD_PATH "/lib" CACHE STRING "Colon-separated list of paths where to look for TAs (see also --ta-dir)")
set(CFG_TEE_FS_PARENT_PATH "/data/tee" CACHE STRING "Location of TEE filesystem (secure storage)")
# FIXME: Why do we have if defined(CFG_GP_SOCKETS) && CFG_GP_SOCKETS == 1 in the c-file?
set(CFG_GP_SOCKETS "1" CACHE STRING "Enable GlobalPlatform Socket API support")
set(CFG_TEE_PLUGIN_LOAD_PATH "/usr/lib/tee-supplicant/plugins/" CACHE STRING "tee-supplicant's plugins path")

if(CFG_TEE_SUPP_PLUGINS)
	set(CMAKE_INSTALL_RPATH "${CFG_TEE_PLUGIN_LOAD_PATH}")
endif()

################################################################################
# Source files
################################################################################
set(SRC
	src/handle.c
	src/hmac_sha2.c
	src/rpmb.c
	src/sha2.c
	src/tee_supp_fs.c
	src/tee_supplicant.c
	src/teec_ta_load.c
)

if(CFG_GP_SOCKETS)
	set(SRC ${SRC} src/tee_socket.c)
endif()

if(CFG_TA_GPROF_SUPPORT OR CFG_FTRACE_SUPPORT)
	set(SRC ${SRC} src/prof.c)
endif()

if(CFG_TEE_SUPP_PLUGINS)
	set(SRC ${SRC} src/plugin.c)
endif()

################################################################################
# Built binary
################################################################################
add_executable(${PROJECT_NAME} ${SRC})

################################################################################
# Flags always set
################################################################################
target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DDEBUGLEVEL_${CFG_TEE_SUPP_LOG_LEVEL}
	PRIVATE -DTEEC_LOAD_PATH="${CFG_TEE_CLIENT_LOAD_PATH}"
	PRIVATE -DTEE_FS_PARENT_PATH="${CFG_TEE_FS_PARENT_PATH}"
	PRIVATE -DBINARY_PREFIX="TSUP"
)

################################################################################
# Optional flags
################################################################################
if(CFG_GP_SOCKETS)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DCFG_GP_SOCKETS=${CFG_GP_SOCKETS})
endif()

if(CFG_TA_TEST_PATH)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DCFG_TA_TEST_PATH=${CFG_TA_TEST_PATH})
endif()

if(RPMB_EMU)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DRPMB_EMU=1)
endif()

if(CFG_TA_GPROF_SUPPORT)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DCFG_TA_GPROF_SUPPORT)
endif()

if(CFG_FTRACE_SUPPORT)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DCFG_FTRACE_SUPPORT)
endif()

if(CFG_TEE_SUPP_PLUGINS)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE -DTEE_SUPP_PLUGINS
		PRIVATE -DTEE_PLUGIN_LOAD_PATH="${CFG_TEE_PLUGIN_LOAD_PATH}"
	)
endif()

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries(${PROJECT_NAME}
	PRIVATE teec
)

if(CFG_TEE_SUPP_PLUGINS)
	target_link_libraries(${PROJECT_NAME}
		PRIVATE dl
	)
endif()

################################################################################
# Install targets
################################################################################
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
