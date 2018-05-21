project (optee-cryptoki-headers C)

add_library(${PROJECT_NAME} INTERFACE)
#target_include_directories(optee_cryptoki PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
	   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
