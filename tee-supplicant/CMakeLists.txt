project(tee-supplicant C)

################################################################################
# Configuration flags always included
################################################################################
option(RPMB_EMU "Enable tee-supplicant to emulate RPMB" ON)
option(CFG_TA_GPROF_SUPPORT "Enable tee-supplicant support for TAs instrumented with gprof" ON)
option(CFG_FTRACE_SUPPORT "Enable tee-supplicant support for TAs instrumented with ftrace" ON)
option(CFG_TEE_SUPP_PLUGINS "Enable tee-supplicant plugin support" ON)
option(CFG_ENABLE_SYSTEMD "Enable systemd service unit file generation." ON)
option(CFG_ENABLE_UDEV "Enable udev rules file generation." ON)
option(CFG_USE_PKGCONFIG "Use pkg-config for discovering install target directory for systemd and udev files." OFF)

set(CFG_TEE_SUPP_LOG_LEVEL "1" CACHE STRING "tee-supplicant log level")
# FIXME: Question is, is this really needed? Should just use defaults from # GNUInstallDirs?
set(CFG_TEE_CLIENT_LOAD_PATH "/lib" CACHE STRING "Colon-separated list of paths where to look for TAs (see also --ta-dir)")
set(CFG_TEE_FS_PARENT_PATH "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/tee" CACHE STRING "Location of TEE filesystem (secure storage)")
# FIXME: Why do we have if defined(CFG_GP_SOCKETS) && CFG_GP_SOCKETS == 1 in the c-file?
set(CFG_GP_SOCKETS "1" CACHE STRING "Enable GlobalPlatform Socket API support")
set(CFG_TEE_PLUGIN_LOAD_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/plugins/" CACHE STRING "tee-supplicant's plugins path")
set(CFG_UDEV_RULESPREFIX "60-" CACHE STRING "Priority prefix for udev rule")

set(CFG_TEE_GROUP "tee" CACHE STRING "Group which has access to /dev/tee* devices")
set(CFG_TEEPRIV_GROUP "teepriv" CACHE STRING "Group which has access to /dev/teepriv* devices")
set(CFG_TEE_SUPPL_USER "teesuppl" CACHE STRING "User account which tee-supplicant is started with")
set(CFG_TEE_SUPPL_GROUP "teesuppl" CACHE STRING "Group account which tee-supplicant is started with")

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
	src/sd_notify.c
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
target_include_directories(${PROJECT_NAME}
	PRIVATE src
	PRIVATE ../libteec/src
)

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
# Discover target install location of the systemd and udev files using pkg-config
if (CFG_USE_PKGCONFIG)
	# Note: pkg-config should return setting valid for the target platform and not the host.
	include(FindPkgConfig)
	if (PKG_CONFIG_FOUND)
		pkg_search_module(SYSTEMD systemd)
		if (SYSTEMD_FOUND AND CFG_ENABLE_SYSTEMD)
			pkg_get_variable(UNIT_DIR systemd systemd_system_unit_dir)
			set(SYSTEMD_UNIT_DIR "${UNIT_DIR}" CACHE PATH "Location of systemd unit files.")
			unset(UNIT_DIR)
		endif()
		pkg_search_module(UDEV udev)
		if (UDEV_FOUND)
			pkg_get_variable(UDEV_DIR udev udev_dir)
			set(UDEV_UDEV_DIR "${UDEV_DIR}" CACHE PATH "Location of udev files.")
			unset(UDEV_DIR)
		endif()
	endif()
endif()

# Some sane defaults if discovering through pkgconfig fails or is disabled.
set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_LIBDIR}/systemd/system" CACHE PATH "Location of systemd unit files.")
set(UDEV_UDEV_DIR "${CMAKE_INSTALL_SYSCONFDIR}/udev/rules.d" CACHE PATH "Location of udev files.")

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
if (CFG_ENABLE_SYSTEMD)
	configure_file(tee-supplicant@.service.in tee-supplicant@.service @ONLY)
	install(FILES ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/tee-supplicant@.service DESTINATION ${SYSTEMD_UNIT_DIR})
endif()
if (CFG_ENABLE_UDEV)
	configure_file(optee-udev.rules.in ${CFG_UDEV_RULESPREFIX}optee-udev.rules @ONLY)
	install(FILES ${CMAKE_BINARY_DIR}/${PROJECT_NAME}/${CFG_UDEV_RULESPREFIX}optee-udev.rules DESTINATION ${UDEV_UDEV_DIR})
endif()
