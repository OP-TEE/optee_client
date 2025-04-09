cmake_minimum_required(VERSION 3.5)
project(optee_client C)

# https://cmake.org/Wiki/CMake_Useful_Variables
set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

option(CFG_WERROR "Build with -Werror" TRUE)
option(WITH_TEEACL "Build libteeacl" TRUE)

include(GNUInstallDirs)

################################################################################
# Compiler flags:
#   We want to use the same flags in the entire optee_client git
################################################################################
add_compile_options(
	-Wall -Wbad-function-cast -Wcast-align
	-Werror-implicit-function-declaration -Wextra
	-Wfloat-equal -Wformat-nonliteral -Wformat-security
	-Wformat=2 -Winit-self -Wmissing-declarations
	-Wmissing-format-attribute -Wmissing-include-dirs
	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs
	-Wpointer-arith -Wshadow -Wstrict-prototypes
	-Wswitch-default -Wwrite-strings -fPIC
)
if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(
        -Wunsafe-loop-optimizations
    )
endif()
if(CFG_WERROR)
    add_compile_options(-Werror)
endif(CFG_WERROR)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

add_subdirectory(libteec)
add_subdirectory(tee-supplicant)
add_subdirectory(libckteec)
if(WITH_TEEACL)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(uuid REQUIRED IMPORTED_TARGET uuid)
    add_subdirectory(libteeacl)
endif(WITH_TEEACL)
add_subdirectory(libseteec)
