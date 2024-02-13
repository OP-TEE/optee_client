project(teeacl
	VERSION 0.1.0
	LANGUAGES C
)

include(GNUInstallDirs)

################################################################################
# Source files
################################################################################
set(SRC
	src/group.c
	src/tee_uuid.c
)

################################################################################
# Built library
################################################################################
add_library(teeacl ${SRC})

configure_file(teeacl.pc.in teeacl.pc @ONLY)

set_target_properties(teeacl PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions(teeacl
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(teeacl PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

target_link_libraries(teeacl
	PUBLIC PkgConfig::uuid
)

################################################################################
# Install targets
################################################################################
install(TARGETS teeacl
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/teeacl.pc"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
