STATIC_LIB ?= y
DEBUG ?= y
WPA_ENTERPRISE ?= n
#enable/disable wireless simple config (WPS) support
CONFIG_EAP_WSC ?= y
ETH_SUPPORT ?=y


WILINK_ROOT = ../../..
CUDK_ROOT ?= $(WILINK_ROOT)/CUDK
LOGGER_ROOT = $(CUDK_ROOT)/logger/linux
OUTPUT_DIR ?= $(CUDK_ROOT)/output
TI_OS_LIB_DIR=$(CUDK_ROOT)/output
ifeq ($(STATIC_LIB),y)
        TI_OS_LIB = tiOsLib.a
else
        TI_OS_LIB = tiOsLib.so
endif

ifeq ($(DEBUG),y)
  DEBUGFLAGS = -O2 -g -DDEBUG -DTI_DBG -fno-builtin   
else
  DEBUGFLAGS = -O2
endif

DEBUGFLAGS+= -DHOST_COMPILE

ifeq ($(WPA_ENTERPRISE), y)
	DK_DEFINES = -D WPA_ENTERPRISE
endif

ifeq ($(ETH_SUPPORT), y)
	DK_DEFINES += -DETH_SUPPORT
endif


TARGET := $(OUTPUT_DIR)/wlan_logger
SRCS  := \
	src/logger.c \
	src/log_conn.c \
	src/log_cmd.c \
	src/log_common.c

OBJS = $(SRCS:.c=.o)

DEPS = $(SRCS:%.c=%.d)

ARMFLAGS  = -fno-common -pipe

INCLUDES = \
	-I inc \
	-I $(CUDK_ROOT)/os/linux/inc \
	-I $(CUDK_ROOT)/os/common/inc \
	-I $(WILINK_ROOT)/utils \
	-I $(WILINK_ROOT)/TWD/TWDriver \
	-I $(WILINK_ROOT)/TWD/FirmwareApi \
	-I $(WILINK_ROOT)/TWD/FW_Transfer/Export_Inc \
	-I $(WILINK_ROOT)/TWD/TwIf \
	-I $(WILINK_ROOT)/Txn \
	-I $(WILINK_ROOT)/stad/Export_Inc \
	-I $(WILINK_ROOT)/stad/src/Application \
	-I $(WILINK_ROOT)/platforms/os/linux/inc \
	-I $(WILINK_ROOT)/platforms/os/common/inc \
	-I $(KERNEL_DIR)/include

CFLAGS = $(OPT) -Wall -Wstrict-prototypes $(DEBUGFLAGS) $(INCLUDES) -D__LINUX__ $(DK_DEFINES) -D__BYTE_ORDER_LITTLE_ENDIAN
CFLAGS += -DDRV_NAME='"tiwlan"'

ifneq "$(CROSS_COMPILE)" ""		#compile for ARM
	CFLAGS += $(ARMFLAGS)
        # strip symbols
ifneq "$(DEBUG)" "y"
    LDFLAGS = -s
endif

endif    # CROSS_COMPILE != ""

.PHONY: all

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CROSS_COMPILE)gcc  --static $(OBJS) $(TI_OS_LIB_DIR)/$(TI_OS_LIB)  -L $(CUDK_ROOT)/Output $(LDFLAGS) -lpthread -lc -o $@
ifeq ($(DEBUG), y)
	cp -a $(TARGET) $(TARGET)_debug
	$(CROSS_COMPILE)strip -s $(TARGET)
endif    #DEBUG

ifeq ("$(findstring $(MAKECMDGOALS), clean cleanall)", "")
-include .depend
endif

%.o: %.cpp
	@echo $@
	@$(CROSS_COMPILE)gcc $(CFLAGS) -c $^ -o $@

%.o: %.c
	@echo $@
	@$(CROSS_COMPILE)gcc -s $(CFLAGS) -c $< -o $@

%.i: %.c
	@$(CROSS_COMPILE)gcc $(CFLAGS) -E -c $< > $@

%.d: %.c
	@echo $@
	@$(CROSS_COMPILE)gcc $< -MT$(^:%.c=%.o) -M $(CFLAGS) > $@

%.d: %.cpp
	@echo $@
	@$(CROSS_COMPILE)gcc $< -MT$(^:%.cpp=%.o) -M $(CFLAGS) > $@

.depend: $(DEPS)
	rm -f $@
	for aa in $^; do cat $$aa >> $@; done

.PHONY: clean
clean:
	@echo cleaning configuration utility...
	rm -f .depend $(OBJS) $(DEPS) $(SRCS:.c=.i) *.ko .*.cmd .*.flags *.mod.c *~ *.~* $(OUTPUT_DIR)/wlan_logger $(OUTPUT_DIR)/wlan_logger_debug

cleanall: clean	


