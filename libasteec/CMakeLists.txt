project(asteec
	VERSION 1.0.0
	LANGUAGES C
)

add_compile_options(${C_COMPILE_OPTIONS})

include(GNUInstallDirs)

################################################################################
# Source files
################################################################################
set(SRC
	src/asteec.c
)

################################################################################
# Built library
################################################################################
add_library(asteec ${SRC})

configure_file(asteec.pc.in asteec.pc @ONLY)

set_target_properties(asteec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions(asteec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(asteec PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

target_link_libraries(asteec
	PRIVATE teec
)

################################################################################
# Install targets
################################################################################
install(TARGETS asteec
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/asteec.pc"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
