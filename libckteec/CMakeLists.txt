project(ckteec C)

set(MAJOR_VERSION 0)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)

set(PROJECT_VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

include(GNUInstallDirs)

################################################################################
# Source files
################################################################################
set (SRC
	src/pkcs11_api.c
	src/ck_debug.c
	src/ck_helpers.c
	src/invoke_ta.c
	src/pkcs11_processing.c
	src/pkcs11_token.c
	src/serializer.c
	src/serialize_ck.c
)

################################################################################
# Built library
################################################################################
add_library (ckteec ${SRC})

set_target_properties (ckteec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${MAJOR_VERSION}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (ckteec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(ckteec
	PUBLIC include
	PRIVATE src
)

target_include_directories(teec
	PUBLIC include
)

target_link_libraries (ckteec
	PRIVATE pthread
	PRIVATE teec
	PRIVATE m
)

################################################################################
# Install targets
################################################################################
install (TARGETS ckteec
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(include)
