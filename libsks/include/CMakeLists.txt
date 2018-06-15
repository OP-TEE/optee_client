project (optee-cryptoki-headers C)

add_library(${PROJECT_NAME} INTERFACE)

install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
	   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
