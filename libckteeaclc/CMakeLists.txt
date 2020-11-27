project(ckteeaclc
	VERSION 0.1.0
	LANGUAGES C
)

include(GNUInstallDirs)

################################################################################
# Source files
################################################################################
set(SRC
	src/cktee_uuid.c
	src/group.c
)

################################################################################
# Built library
################################################################################
add_library (ckteeaclc ${SRC})

set_target_properties(ckteeaclc PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
	C_STANDARD 11
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS ON
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions(ckteeaclc
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(ckteeaclc PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>
)

target_link_libraries(ckteeaclc
	PUBLIC PkgConfig::uuid
)

################################################################################
# Install targets
################################################################################
install(TARGETS ckteeaclc
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
