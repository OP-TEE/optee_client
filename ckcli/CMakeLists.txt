project(teeckcli
	VERSION 0.1.0
	LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 14)

include(GNUInstallDirs)

################################################################################
# Source files
################################################################################
set(SRC
	src/teeckcli.cpp
)

################################################################################
# Build time constants
################################################################################
set(GENERATED_SOURCES_DIR "${CMAKE_BINARY_DIR}/generated-src/teeckcli")
file(MAKE_DIRECTORY "${GENERATED_SOURCES_DIR}")
set(TEECKCLI_VERSION ${PROJECT_VERSION})
configure_file(src/TeeCkCliConstants.cpp.in "${GENERATED_SOURCES_DIR}/TeeCkCliConstants.cpp")
add_library(teeckcli-constants OBJECT "${GENERATED_SOURCES_DIR}/TeeCkCliConstants.cpp")
target_include_directories(teeckcli-constants PUBLIC src)

################################################################################
# Built executable
################################################################################
add_executable(teeckcli ${SRC})
target_link_libraries(teeckcli teeckcli-constants docopt ckteecpp ckteeaclc)

################################################################################
# Install targets
################################################################################
install(TARGETS teeckcli
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
