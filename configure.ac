AC_PREREQ(2.59)
AC_INIT([optee-client], [2.6.0], [optee@linaro.org])

# foreign: avoid having to have some GNU mandated files (AUTHORS, COPYING, etc)
# TODO: more permissive option?
# subdir-objects: source may be in subdirectories.
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_FILES([Makefile
		 tee-supplicant/Makefile
		 libteec/Makefile
		 optee_client.pc])

# Current compatibility expect libteec.so.0.1.0
# Strict to this in the libtool versioning format.
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info
LIBTEEC_CURRENT=1
LIBTEEC_REVISION=0
LIBTEEC_AGE=1
LIBTEEC_MAJOR=0
LIBTEEC_MINOR=1
LIBTEEC_MICRO=0
AC_SUBST([LIBTEEC_CURRENT])
AC_SUBST([LIBTEEC_REVISION])
AC_SUBST([LIBTEEC_AGE])
AC_SUBST([LIBTEEC_MAJOR])
AC_SUBST([LIBTEEC_MINOR])
AC_SUBST([LIBTEEC_MICRO])

# Configuration env variables for the OP-TEE build environment:
# CFG_TA_TEST_PATH
# CFG_TA_GPROF_SUPPORT
# CFG_TEE_BENCHMARK
# CFG_TEE_CLIENT_LOG_LEVEL
# CFG_TEE_SUPP_LOG_LEVEL
# CFG_TEE_CLIENT_LOG_FILE
# CFG_TEE_SUPP_LOG_FILE
# CFG_TEE_CLIENT_LOAD_PATH
# CFG_TEE_FS_PARENT_PATH
# CFG_GP_SOCKETS
# Extra optee_client specific settings:
# DEBUG
# RPMB_EMU

AC_ARG_VAR([DEBUG],
	   [Define to any value to enable debug mode.])
AM_CONDITIONAL([DEBUG], [test x"$DEBUG" != x])

AC_ARG_VAR([RPMB_EMU],
	   [Define to 1 to enable RPMB emulation. TODO add desc.])
test -z "$RPMB_EMU" && RPMB_EMU=1
AM_CONDITIONAL([RPMB_EMU], [test x"$RPMB_EMU" != x1])

AC_ARG_VAR([CFG_TA_TEST_PATH],
	   [Define to y to enable test on TA binaries])
test -z "$CFG_TA_TEST_PATH" && CFG_TA_TEST_PATH=y
AM_CONDITIONAL([CFG_TA_TEST_PATH], [test x"$CFG_TA_TEST_PATH" = xy])

AC_ARG_VAR([CFG_TA_GPROF_SUPPORT],
	   [Define to y to enable dumps of the TA profiling info.])
test -z "$CFG_TA_GPROF_SUPPORT" && CFG_TA_GPROF_SUPPORT=n
AM_CONDITIONAL([CFG_TA_GPROF_SUPPORT], [test x"$CFG_TA_GPROF_SUPPORT" = xy])

AC_ARG_VAR([CFG_TEE_BENCHMARK],
	   [Define to y to enable TEE benchmark support in OP-TEE
	    Client API library.])
test -z "$CFG_TEE_BENCHMARK" && CFG_TEE_BENCHMARK=n
AM_CONDITIONAL([CFG_TEE_BENCHMARK], [test x"$CFG_TEE_BENCHMARK" = xy])

AC_ARG_VAR([CFG_TEE_CLIENT_LOG_LEVEL],
	   [Numerical log level of the OP-TEE Client API library.])
test -z "$CFG_TEE_CLIENT_LOG_LEVEL" && CFG_TEE_CLIENT_LOG_LEVEL=2
AC_SUBST([CFG_TEE_CLIENT_LOG_LEVEL])

AC_ARG_VAR([CFG_TEE_SUPP_LOG_LEVEL],
	   [Numerical log level of the OP-TEE supplicant application.])
test -z "$CFG_TEE_SUPP_LOG_LEVEL" && CFG_TEE_SUPP_LOG_LEVEL=2
AC_SUBST([CFG_TEE_SUPP_LOG_LEVEL])

AC_ARG_VAR([CFG_TEE_CLIENT_LOG_FILE],
	   [The location of the client log file when logging to file is enabled.])
test -z "$CFG_TEE_CLIENT_LOG_FILE" && CFG_TEE_CLIENT_LOG_FILE=/data/teec.log
AC_SUBST([CFG_TEE_CLIENT_LOG_FILE])

AC_ARG_VAR([CFG_TEE_SUPP_LOG_FILE],
	   [The location of the supplicant log file when logging to file is enabled.])
test -z "$CFG_TEE_SUPP_LOG_FILE" && CFG_TEE_SUPP_LOG_FILE=/data/teesupp.log
AC_SUBST([CFG_TEE_SUPP_LOG_FILE])

AC_ARG_VAR([CFG_TEE_CLIENT_LOAD_PATH],
	   [Root directory where the tee-supplicant get the TA binaries.])
test -z "$CFG_TEE_CLIENT_LOAD_PATH" && CFG_TEE_CLIENT_LOAD_PATH=/lib
AC_SUBST([CFG_TEE_CLIENT_LOAD_PATH])

AC_ARG_VAR([CFG_TEE_FS_PARENT_PATH],
	   [Path to folder that will contain TEE filesystem.
	    This folder should be created before tee-supplicant start.])
test -z "$CFG_TEE_FS_PARENT_PATH" && CFG_TEE_FS_PARENT_PATH=/data
AC_SUBST([CFG_TEE_FS_PARENT_PATH])

AC_ARG_VAR([CFG_GP_SOCKETS],
	   [Define to y to enable Global Platform Sockets support.])
test "$CFG_GP_SOCKETS" == "y" || CFG_GP_SOCKETS=n
AM_CONDITIONAL([CFG_GP_SOCKETS], [test x"$CFG_GP_SOCKETS" = xy])

# Some warning flags we would like to always apply on build components
WARNINGCFLAGS="\\
	-Wall -Wbad-function-cast -Wcast-align \\
	-Werror-implicit-function-declaration -Wextra \\
	-Wfloat-equal -Wformat-nonliteral -Wformat-security \\
	-Wformat=2 -Winit-self -Wmissing-declarations \\
	-Wmissing-format-attribute -Wmissing-include-dirs \\
	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs \\
	-Wpointer-arith -Wshadow -Wstrict-prototypes \\
	-Wswitch-default -Wunsafe-loop-optimizations \\
	-Wwrite-strings -Werror \\
	"

AC_SUBST([WARNINGCFLAGS])

# Force disabling CC default optimization in debug mode.
# This must be done before AC_PROG_CC.
DEBUGCFLAGS="-DDEBUG -O0 -g"
AM_COND_IF([DEBUG], [CFLAGS=$DEBUGCFLAGS])

dnl checks for programs
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_CC_C99
AC_PROG_LIBTOOL
AC_PROG_MKDIR_P
AC_PROG_LN_S
PKG_PROG_PKG_CONFIG
AC_SUBST([pkgconfigdir], [$libdir/pkgconfig])

dnl checks for libraries
AC_MSG_CHECKING([if we have pthread support])
PTHREAD_LIBS=error
AC_CHECK_LIB(pthread, pthread_create, PTHREAD_LIBS="-lpthread")
AC_SUBST(PTHREAD_LIBS)

AC_MSG_CHECKING([if we have rt support])
RT_LIBS=error
AC_CHECK_LIB(rt, clock_gettime, RT_LIBS="-lrt")
AC_SUBST(RT_LIBS)

dnl checks for headers
dnl checks for types
dnl checks for structures
dnl checks for compiler characteristics
dnl checks for library functions
dnl checks for system services

AC_OUTPUT
