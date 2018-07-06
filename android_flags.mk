#########################################################################
# COMMON COMPILATION FLAGS                                              #
#########################################################################
CFLAGS          := -Wall -Wbad-function-cast -Wcast-align \
		   -Werror-implicit-function-declaration -Wextra \
		   -Wfloat-equal -Wformat-nonliteral -Wformat-security \
		   -Wformat=2 -Winit-self -Wmissing-declarations \
		   -Wmissing-format-attribute  \
		   -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs \
		   -Wpointer-arith -Wshadow -Wstrict-prototypes \
		   -Wswitch-default \
		   -Wwrite-strings
ifeq ($(CFG_WERROR),y)
CFLAGS		+= -Werror
endif
CFLAGS          += -c -fPIC

DEBUG       ?= 0
ifeq ($(DEBUG), 1)
CFLAGS          += -DDEBUG -O0 -g
endif

RM              := rm -rf
