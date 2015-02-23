include ../flags.mk

OUT_DIR		?= ${CURDIR}/../$(O)/libteec

.PHONY: all libteec clean

all: libteec
################################################################################
# Teec configuration
################################################################################
MAJOR_VERSION	:= 1
MINOR_VERSION	:= 0
LIB_NAME	:= libteec.so
LIB_MAJOR	:= $(LIB_NAME).$(MAJOR_VERSION)
LIB_MAJ_MIN	:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION)

TEEC_SRCS	:= tee_client_api.c \
		   teec_trace.c

TEEC_SRC_DIR	:= src
TEEC_OBJ_DIR	:= $(OUT_DIR)
TEEC_OBJS 	:= $(patsubst %.c,$(TEEC_OBJ_DIR)/%.o, $(TEEC_SRCS))
TEEC_INCLUDES 	:= \
		   ${CURDIR}/include \
		   ${CURDIR}/../public \

TEEC_CFLAGS	:= $(addprefix -I, $(TEEC_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
		   -DDEBUGLEVEL_$(CFG_TEE_CLIENT_LOG_LEVEL) \
		   -DBINARY_PREFIX=\"TEEC\"

TEEC_LFLAGS    := -lpthread
TEEC_LIBRARY	:= $(OUT_DIR)/$(LIB_MAJ_MIN)

libteec: $(TEEC_LIBRARY)
	$(VPREFIX)ln -sf $(TEEC_LIBRARY) $(OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(OUT_DIR)/$(LIB_MAJOR) $(OUT_DIR)/$(LIB_NAME)

$(TEEC_LIBRARY): $(TEEC_OBJS)
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_MAJ_MIN) $(TEEC_LFLAGS) -o $@ $+
	@echo ""

$(TEEC_OBJ_DIR)/%.o: ${TEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(TEEC_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(TEEC_CFLAGS) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(OUT_DIR)
