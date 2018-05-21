project(liboptee_cryptoki C)

set(PROJECT_VERSION "1.0.0")

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
)

################################################################################
# Built library
################################################################################
add_library (optee_cryptoki SHARED ${SRC})

set_target_properties (optee_cryptoki PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_NAME}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (optee_cryptoki
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(optee_cryptoki
	PUBLIC include
	PRIVATE src
)

target_include_directories(teec
	PUBLIC include
)

target_link_libraries (optee_cryptoki
	PRIVATE pthread
	PRIVATE teec
	PRIVATE m
)

################################################################################
# Install targets
################################################################################
install (TARGETS optee_cryptoki
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(include)
