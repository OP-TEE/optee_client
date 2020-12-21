include ../flags.mk
include ../config.mk

CXX	?= $(CROSS_COMPILE)g++

CXXFLAGS	?= -Wall -Wcast-align -Wextra -Wfloat-equal \
		-Wformat-nonliteral -Wformat-security -Wformat=2 \
		-Winit-self -Wmissing-declarations \
		-Wmissing-format-attribute -Wmissing-include-dirs \
		-Wmissing-noreturn -Wpointer-arith -Wshadow \
		-Wswitch-default -Wunsafe-loop-optimizations \
		-Wwrite-strings -fPIC
ifeq ($(CFG_WERROR),y)
CXXFLAGS	+= -Werror
endif
CXXFLAGS	+= -c -fPIC

DEBUG		?= 0
ifeq ($(DEBUG),1)
CXXFLAGS	+= -DDEBUG=1 -O0 -g
endif

OUT_DIR := $(OO)/ckcli

.PHONY: all teeckcli clean

all: teeckcli

TEECKCLI_VERSION	:= 0.1.0
# Write version to file so that it can be used for up-to-date checks
TEECKCLI_VERSION_FILE	:= $(OUT_DIR)/metadata/version
$(shell mkdir -p $(dir $(TEECKCLI_VERSION_FILE)); echo $(TEECKCLI_VERSION) | \
	diff $(TEECKCLI_VERSION_FILE) - > /dev/null || \
	echo $(TEECKCLI_VERSION) > $(TEECKCLI_VERSION_FILE) )

GENERATED_SOURCES_DIR	:= $(OO)/generated-src/teeckcli
$(GENERATED_SOURCES_DIR):
	mkdir -p $(GENERATED_SOURCES_DIR)

TEECKCLI_CONSTANTS_CPP	:= $(GENERATED_SOURCES_DIR)/TeeCkCliConstants.cpp
$(TEECKCLI_CONSTANTS_CPP): $(GENERATED_SOURCES_DIR) $(TEECKCLI_VERSION_FILE) src/TeeCkCliConstants.cpp.in
	sed 's/$${TEECKCLI_VERSION}/${TEECKCLI_VERSION}/g' src/TeeCkCliConstants.cpp.in > $(TEECKCLI_CONSTANTS_CPP)

TEECKCLI_SRCS	:= teeckcli.cpp

TEECKCLI_SRC_DIR	:= src
TEECKCLI_OBJ_DIR	:= $(OUT_DIR)
TEECKCLI_CONSTANTS_OBJ := $(patsubst %.cpp,$(TEECKCLI_OBJ_DIR)/%.o, TeeCkCliConstants.cpp)
TEECKCLI_OBJS 	:= $(patsubst %.cpp,$(TEECKCLI_OBJ_DIR)/%.o, $(TEECKCLI_SRCS)) \
		$(TEECKCLI_CONSTANTS_OBJ)
TEECKCLI_INCLUDES := ${CURDIR}/../libteec/include \
		${CURDIR}/../public \
		${CURDIR}/../libckteec/include \
		${CURDIR}/../libckteeaclc/include \
		${CURDIR}/../ckteecpp/include \
		${CURDIR}/src

TEECKCLI_CXXFLAGS	:= $(addprefix -I, $(TEECKCLI_INCLUDES)) \
		$(shell pkg-config --cflags uuid) \
		$(CXXFLAGS) -D_GNU_SOURCE -fPIC

TEECKCLI_FILE 	:= $(OUT_DIR)/teeckcli
TEECKCLI_LFLAGS	:= $(LDFLAGS) -L$(OUT_DIR)/../libteec -lteec \
		-L$(OUT_DIR)/../libckteec -lckteec \
		-L$(OUT_DIR)/../libckteeaclc -lckteeaclc \
		$(shell pkg-config --libs docopt)

teeckcli: $(TEECKCLI_FILE)

$(TEECKCLI_FILE): $(TEECKCLI_OBJS)
	@echo "  LINK    $@"
	$(VPREFIX)$(CXX) -o $@ $+ $(TEECKCLI_LFLAGS)
	@echo ""

$(TEECKCLI_CONSTANTS_OBJ): $(TEECKCLI_CONSTANTS_CPP)
	$(VPREFIX)mkdir -p $(TEECKCLI_OBJ_DIR)
	@echo "  CXX      $<"
	$(VPREFIX)$(CXX) $(TEECKCLI_CXXFLAGS) $(TEECKCLI_CXXFLAGS_$(notdir $<)) -c $< -o $@

$(TEECKCLI_OBJ_DIR)/%.o: $(TEECKCLI_SRC_DIR)/%.cpp
	$(VPREFIX)mkdir -p $(TEECKCLI_OBJ_DIR)
	@echo "  CXX      $<"
	$(VPREFIX)$(CXX) $(TEECKCLI_CXXFLAGS) $(TEECKCLI_CXXFLAGS_$(notdir $<)) -c $< -o $@

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(TEECKCLI_OBJS) $(TEECKCLI_FILE)
	$(call rmdir,$(OUT_DIR))
