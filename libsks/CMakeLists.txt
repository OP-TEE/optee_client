project(liboptee_cryptoki C)

set(PROJECT_VERSION "1.0.0")

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

################################################################################
# Source files
################################################################################
set (SRC
	src/pkcs11_api.c
	src/ck_debug.c
	src/ck_helpers.c
	src/invoke_ta.c
	src/pkcs11_token.c
	src/serializer.c
	src/serialize_ck.c
)

################################################################################
# Built library
################################################################################
add_library (optee_cryptoki SHARED ${SRC})

set_target_properties (teec PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_NAME}
)

################################################################################
# Flags always set
################################################################################
target_compile_definitions (teec
	PRIVATE -D_GNU_SOURCE
	PRIVATE -DBINARY_PREFIX="LT"
)

################################################################################
# Optional flags
################################################################################

################################################################################
# Public and private header and library dependencies
################################################################################
target_include_directories(teec PUBLIC include)

target_link_libraries (optee_cryptoki
	PUBLIC ${CMAKE_THREAD_LIBS_INIT} # this is pthreads
	PUBLIC optee-client-headers)

################################################################################
# Install targets
################################################################################
install (TARGETS optee_cryptoki DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include
	   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

