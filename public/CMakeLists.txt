project (optee-client-headers C)

################################################################################
# Built library
################################################################################
add_library(${PROJECT_NAME} INTERFACE)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(teec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

################################################################################
# Install targets
################################################################################
install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
	   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
