project (optee-client-headers C)

add_compile_options(${C_COMPILE_OPTIONS})

################################################################################
# Header files to be exported
################################################################################
FILE(GLOB INSTALL_HEADERS "*.h")

################################################################################
# Built library
################################################################################
add_library(${PROJECT_NAME} INTERFACE)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(
	${PROJECT_NAME}
	INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:{CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(
        teec
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:{CMAKE_INSTALL_INCLUDEDIR}>
)

################################################################################
# Install targets
################################################################################
install (FILES ${INSTALL_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
