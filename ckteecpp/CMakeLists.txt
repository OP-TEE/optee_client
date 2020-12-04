project(ckteecpp CXX)

add_library(${PROJECT_NAME} INTERFACE)

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(
    ${PROJECT_NAME}
    INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME} INTERFACE ckteec ckteeaclc)

################################################################################
# Install targets
################################################################################
install(DIRECTORY include/${PROJECT_NAME}
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS ${PROJECT_NAME}
	PUBLIC_HEADER
) # no EXPORT yet, so a no-op
