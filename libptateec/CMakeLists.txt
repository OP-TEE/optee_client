project(ptateec
	VERSION 0.1.0
	LANGUAGES C)

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
	src/pta.c
	src/pta_imx_manufacturing_protection.c
)

################################################################################
# Built library
################################################################################
add_library (ptateec ${SRC})

set_target_properties (ptateec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (ptateec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(ptateec
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
	PRIVATE src
)

target_link_libraries (ptateec
	PRIVATE pthread
	PRIVATE teec
)

################################################################################
# Install targets
################################################################################
install (TARGETS ptateec
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(include)
