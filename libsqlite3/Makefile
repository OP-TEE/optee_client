include ../flags.mk

O ?= out
OUT_DIR	?= ${CURDIR}/../$(O)/libsqlite3

.PHONY: all libsqlite3 clean

all: libsqlite3
################################################################################
# SQLite3 configuration
################################################################################
LIB_NAME := libsqlite3.a
SQLITE3_SRCS := sqlite3.c
SQLITE3_SRC_DIR := src
SQLITE3_OBJ_DIR := $(OUT_DIR)
SQLITE3_OBJS := $(patsubst %.c,$(SQLITE3_OBJ_DIR)/%.o, $(SQLITE3_SRCS))
SQLITE3_INCLUDES := ${CURDIR}/include
SQLITE3_CFLAGS_REMOVE := -Wall -Wbad-function-cast -Wswitch-default \
	-Wfloat-equal -Werror -Wwrite-strings -Wcast-align
SQLITE3_CFLAGS := $(addprefix -I, $(SQLITE3_INCLUDES)) \
	$(filter-out $(SQLITE3_CFLAGS_REMOVE),$(CFLAGS))
SQLITE3_LFLAGS :=
SQLITE3_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)

libsqlite3: $(SQLITE3_LIBRARY)

$(SQLITE3_LIBRARY): $(SQLITE3_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) cr $@ $^
	@echo ""

$(SQLITE3_OBJ_DIR)/%.o: ${SQLITE3_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(SQLITE3_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(SQLITE3_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(OUT_DIR)
