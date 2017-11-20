AM_CFLAGS	= -Wall -Wbad-function-cast -Wcast-align \
		  -Werror-implicit-function-declaration -Wextra \
		  -Wfloat-equal -Wformat-nonliteral -Wformat-security \
		  -Wformat=2 -Winit-self -Wmissing-declarations \
		  -Wmissing-format-attribute -Wmissing-include-dirs \
		  -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs \
		  -Wpointer-arith -Wshadow -Wstrict-prototypes \
		  -Wswitch-default -Wunsafe-loop-optimizations \
		  -Wwrite-strings -Werror

if DEBUG
AM_CFLAGS	+= -DDEBUG -O0 -g
endif

SUBDIRS = libteec tee-supplicant

pkgconfig_DATA = optee_client.pc
