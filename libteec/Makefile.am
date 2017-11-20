include_HEADERS = $(top_srcdir)/public/tee_bench.h
include_HEADERS += $(top_srcdir)/public/tee_client_api_extensions.h
include_HEADERS += $(top_srcdir)/public/tee_client_api.h
include_HEADERS += $(top_srcdir)/public/teec_trace.h

lib_LTLIBRARIES	= libteec.la

AM_CFLAGS		= $(WARNINGCFLAGS)

libteec_la_LDFLAGS	= -version-info $(LIBTEEC_CURRENT):$(LIBTEEC_REVISION):$(LIBTEEC_AGE)

libteec_la_SOURCES	= src/tee_client_api.c
libteec_la_SOURCES	+= src/teec_trace.c

libteec_la_CFLAGS	= -I$(top_srcdir)/libteec/include
libteec_la_CFLAGS	+= -I$(top_srcdir)/public

libteec_la_CFLAGS	+= -D_GNU_SOURCE
libteec_la_CFLAGS	+= -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL)
libteec_la_CFLAGS	+= -DBINARY_PREFIX=\"TEEC\"

if CFG_TEE_BENCHMARK
libteec_la_CFLAGS	+= -DCFG_TEE_BENCHMARK
libteec_la_SOURCES	+= src/teec_benchmark.c
endif

libteec_la_CFLAGS	+= $(AM_CFLAGS)
libteec_la_CFLAGS	+= $(PTHREAD_CFLAGS)

# install libteec.so.x.y which is not installed by the autotools
install-exec-hook:
	test -e $(DESTDIR)/$(libdir)/libteec.so.$(LIBTEEC_MAJOR).$(LIBTEEC_MINOR).$(LIBTEEC_MICRO)
	$(LN_S) -f libteec.so.$(LIBTEEC_MAJOR).$(LIBTEEC_MINOR).$(LIBTEEC_MICRO) \
		$(DESTDIR)/$(libdir)/libteec.so.$(LIBTEEC_MAJOR).$(LIBTEEC_MINOR)
