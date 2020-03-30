include ../flags.mk
include ../config.mk

OUT_DIR := $(OO)/libteec

.PHONY: all libteec clean

all: libteec
################################################################################
# Teec configuration
################################################################################
MAJOR_VERSION	:= 1
MINOR_VERSION	:= 0
PATCH_VERSION	:= 0
LIB_NAME	:= libteec.so
LIB_MAJOR	:= $(LIB_NAME).$(MAJOR_VERSION)
LIB_MAJ_MIN	:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_P	:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)

TEEC_SRCS	:= tee_client_api.c \
		   teec_trace.c
ifeq ($(CFG_TEE_BENCHMARK),y)
TEEC_SRCS	+= teec_benchmark.c
endif

TEEC_SRC_DIR	:= src
TEEC_OBJ_DIR	:= $(OUT_DIR)
TEEC_OBJS 	:= $(patsubst %.c,$(TEEC_OBJ_DIR)/%.o, $(TEEC_SRCS))
TEEC_INCLUDES 	:= \
		   ${CURDIR}/include \
		   ${CURDIR}/../public \

TEEC_CFLAGS	:= $(addprefix -I, $(TEEC_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
		   -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"TEEC\"

ifeq ($(CFG_TEE_BENCHMARK),y)
TEEC_CFLAGS	+= -DCFG_TEE_BENCHMARK
endif

TEEC_LFLAGS    := $(LDFLAGS) -lpthread
TEEC_LIBRARY	:= $(OUT_DIR)/$(LIB_MAJ_MIN_P)

libteec: $(TEEC_LIBRARY) $(OUT_DIR)/libteec.a
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_P) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_P) $(OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME)

$(TEEC_LIBRARY): $(TEEC_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJOR) -o $@ $+ $(TEEC_LFLAGS)
	@echo ""

$(OUT_DIR)/libteec.a: $(TEEC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $+

$(TEEC_OBJ_DIR)/%.o: ${TEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(TEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEEC_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(TEEC_OBJS) $(TEEC_LIBRARY) $(OUT_DIR)/$(LIB_MAJOR) \
		$(OUT_DIR)/$(LIB_MAJ_MIN) $(OUT_DIR)/$(LIB_NAME)
	$(RM) $(OUT_DIR)/libteec.a
	$(call rmdir,$(OUT_DIR))
