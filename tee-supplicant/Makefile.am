bin_PROGRAMS = tee_supplicant

AM_CFLAGS		= $(WARNINGCFLAGS)

tee_supplicant_SOURCES	= src/tee_supplicant.c
tee_supplicant_SOURCES	+= src/teec_ta_load.c
tee_supplicant_SOURCES	+= src/tee_supp_fs.c
tee_supplicant_SOURCES	+= src/rpmb.c
tee_supplicant_SOURCES	+= src/handle.c

tee_supplicant_CFLAGS	= -I$(top_srcdir)/libteec/include
tee_supplicant_CFLAGS	+= -I$(top_srcdir)/tee-supplicant/src
tee_supplicant_CFLAGS	+= -I$(top_srcdir)/public

tee_supplicant_CFLAGS	+= $(PTHREAD_CFLAGS)
tee_supplicant_CFLAGS	+= -DDEBUGLEVEL_$(CFG_TEE_SUPP_LOG_LEVEL)
tee_supplicant_CFLAGS	+= -DBINARY_PREFIX=\"TEES\"
tee_supplicant_CFLAGS	+= -DTEE_FS_PARENT_PATH=\"$(CFG_TEE_FS_PARENT_PATH)\"
tee_supplicant_CFLAGS	+= -DTEEC_LOAD_PATH=\"$(CFG_TEE_CLIENT_LOAD_PATH)\"
if CFG_TA_TEST_PATH
tee_supplicant_CFLAGS	+= -DCFG_TA_TEST_PATH
endif

if CFG_GP_SOCKETS
tee_supplicant_CFLAGS	+= -DCFG_GP_SOCKETS=1
tee_supplicant_SOURCES	+= src/tee_socket.c
endif
if RPMB_EMU
tee_supplicant_CFLAGS	+= -DRPMB_EMU
tee_supplicant_SOURCES	+= src/sha2.c src/hmac_sha2.c
endif
if CFG_TA_GPROF_SUPPORT
tee_supplicant_CFLAGS	+= -DCFG_TA_GPROF_SUPPORT
tee_supplicant_SOURCES	+= src/gprof.c
endif

# Get the libteec built from this package
LIBTEEC = $(top_builddir)/libteec/libteec.la

tee_supplicant_CFLAGS	+= $(AM_CFLAGS)
tee_supplicant_LDADD	= $(LIBTEEC) $(PTHREAD_LIBS) $(RT_LIBS)
