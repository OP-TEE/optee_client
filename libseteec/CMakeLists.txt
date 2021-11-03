project(seteec C)

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
	src/se.c
)

################################################################################
# Built library
################################################################################
add_library (seteec ${SRC})

set_target_properties (seteec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${MAJOR_VERSION}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (seteec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(seteec
	PUBLIC include
	PRIVATE src
)

target_include_directories(teec
	PUBLIC include
)

target_link_libraries (seteec
	PRIVATE pthread
	PRIVATE teec
)

################################################################################
# Install targets
################################################################################
install (TARGETS seteec
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(include)
