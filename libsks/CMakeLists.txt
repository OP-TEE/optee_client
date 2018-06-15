project(sks C)

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
add_library (sks SHARED ${SRC})

set_target_properties (sks PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_NAME}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (sks
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(sks
	PUBLIC include
	PRIVATE src
)

target_include_directories(teec
	PUBLIC include
)

target_link_libraries (sks
	PRIVATE pthread
	PRIVATE teec
	PRIVATE m
)

################################################################################
# Install targets
################################################################################
install (TARGETS sks
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(include)
