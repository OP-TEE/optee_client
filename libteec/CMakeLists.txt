project(libteec
	VERSION 2.0.0
	LANGUAGES C)

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

################################################################################
# Configuration flags always included
################################################################################
set(CFG_TEE_CLIENT_LOG_LEVEL "1" CACHE STRING "libteec log level")
set(CFG_TEE_CLIENT_LOG_FILE "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/tee/teec.log" CACHE STRING "Location of libteec log")

################################################################################
# Source files
################################################################################
set(SRC
	src/tee_client_api.c
	src/teec_trace.c
)

################################################################################
# Built library
################################################################################
add_library(teec ${SRC})

set(libteectgt teec)
configure_file(teec.pc.in teec.pc @ONLY)

set_target_properties(teec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions(teec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DDEBUGLEVEL_${CFG_TEE_CLIENT_LOG_LEVEL}
	PRIVATE -DTEEC_LOG_FILE="${CFG_TEE_CLIENT_LOG_FILE}"
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(teec
	PUBLIC include
	PRIVATE src
)

target_link_libraries(teec
	PUBLIC ${CMAKE_THREAD_LIBS_INIT} # this is pthreads
)

################################################################################
# Install targets
################################################################################
install(TARGETS teec LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(DIRECTORY include
	DESTINATION ${CMAKE_INSTALL_PREFIX}
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/teec.pc"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
