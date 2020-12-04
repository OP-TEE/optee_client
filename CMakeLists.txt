cmake_minimum_required (VERSION 3.4)
project (optee_client C)

# https://cmake.org/Wiki/CMake_Useful_Variables
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

set (CFG_WERROR 1 CACHE BOOL "Build with -Werror")

include(GNUInstallDirs)

################################################################################
# Compiler flags:
#   We want to use the same flags in the entire optee_client git
################################################################################
add_compile_options (
	-Wall -Wcast-align -Wextra -Wfloat-equal
	-Wformat-nonliteral -Wformat-security -Wformat=2
	-Winit-self -Wmissing-declarations
	-Wmissing-format-attribute -Wmissing-include-dirs
	-Wmissing-noreturn -Wpointer-arith -Wshadow
	-Wswitch-default -Wunsafe-loop-optimizations
	-Wwrite-strings -fPIC
)
set (C_COMPILE_OPTIONS
	-Wbad-function-cast
	-Werror=implicit-function-declaration
	-Wmissing-prototypes
	-Wnested-externs
	-Wstrict-prototypes
)
if(CFG_WERROR)
    add_compile_options(-Werror)
endif(CFG_WERROR)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

add_subdirectory (libteec)
add_subdirectory (tee-supplicant)
add_subdirectory (public)
add_subdirectory (libckteec)
find_package (PkgConfig REQUIRED)
pkg_check_modules(uuid REQUIRED IMPORTED_TARGET uuid)
add_subdirectory (libckteeaclc)
add_subdirectory (ckteecpp)
