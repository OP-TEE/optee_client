project(libteec C)

set(PROJECT_VERSION "1.0.0")

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
option (CFG_TEE_BENCHMARK "Build with benchmark support" OFF)

set (CFG_TEE_CLIENT_LOG_LEVEL "1" CACHE STRING "libteec log level")
set (CFG_TEE_CLIENT_LOG_FILE "/data/tee/teec.log" CACHE STRING "Location of libteec log")

################################################################################
# Source files
################################################################################
set (SRC
	src/tee_client_api.c
	src/teec_trace.c
)

if (CFG_TEE_BENCHMARK)
	set (SRC ${SRC} src/teec_benchmark.c)
endif()

################################################################################
# Built library
################################################################################
add_library (teec ${SRC})

set_target_properties (teec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (teec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DCFG_TEE_CLIENT_LOG_LEVEL=${CFG_TEE_CLIENT_LOG_LEVEL}
	PRIVATE -DTEEC_LOG_FILE="${CFG_TEE_CLIENT_LOG_FILE}"
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################
if (CFG_TEE_BENCHMARK)
	target_compile_definitions (teec PRIVATE -DCFG_TEE_BENCHMARK)
endif()

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(teec PUBLIC include)

target_link_libraries (teec
	PUBLIC ${CMAKE_THREAD_LIBS_INIT} # this is pthreads
	PRIVATE optee-client-headers)

################################################################################
# Install targets
################################################################################
# FIXME: This should in someway harmonize with CFG_TEE_CLIENT_LOAD_PATH
# FIXME: Should we change this to /usr/local/lib?
install (TARGETS teec LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
