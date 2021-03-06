#
# Build options
#
# compiling the OAL as static lib
STATIC_LIB ?= y
# compiling in debug mode
DEBUG ?= y
# build the supplicant
BUILD_SUPPL ?= y
# type of supplicant to build
SUPPL?=WPA
# enable WPA enterprise authorization modes
WPA_ENTERPRISE ?= y
# add XCC support
XCC ?= n

# Hostapd support
TI_HOSTAPD ?= y

#Hostapd lib support
TI_HOSTAPD_LIB ?= y

#
# Directories and files
#
WILINK_ROOT = ..
CUDK_ROOT ?= $(WILINK_ROOT)/CUDK
CU_DIR = $(CUDK_ROOT)/configurationutility
TI_SUPP_LIB_DIR ?= $(CUDK_ROOT)/wpa_suppl

TI_HOSTAPD_DIR=$(WILINK_ROOT)/CUDK/hostapd/hostapd
TI_HOSTAPD_TARGET=$(TI_HOSTAPD_DIR)/hostapd

LOGGER_DIR = $(CUDK_ROOT)/logger/linux
OUTPUT_DIR ?= $(CUDK_ROOT)/output
TI_OS_LIB_DIR=$(CUDK_ROOT)/os/linux/src
ifeq ($(STATIC_LIB),y)
        TI_OS_LIB = tiOsLib.a
else
        TI_OS_LIB = tiOsLib.so
endif
WLAN_LOADER_DIR = $(CUDK_ROOT)/tiwlan_loader/

ifeq ($(ETH_SUPPORT), y)
DK_DEFINES += -DETH_SUPPORT
endif

#
# Targets
#
CU_TARGET = $(OUTPUT_DIR)/wlan_cu
LOGGER_TARGET = $(OUTPUT_DIR)/wlan_logger
OS_TARGET = $(OUTPUT_DIR)/$(TI_OS_LIB)
LOADER_TARGET = $(OUTPUT_DIR)/tiwlan_loader

ifeq ($(TI_HOSTAPD),y)
ALL_TARGETS = $(TI_HOSTAPD_TARGET) $(OS_TARGET) $(LOADER_TARGET) $(CU_TARGET) $(LOGGER_TARGET) 
else
ALL_TARGETS = $(OS_TARGET) $(LOADER_TARGET) $(CU_TARGET) $(LOGGER_TARGET) 
endif

#Supplicant directory, file and target

ifeq ($(SUPPL),GEM)
  SUPPL_TARGET = $(OUTPUT_DIR)/wpa_supplicant
  TI_SUPP_LIB_DIR = $(CUDK_ROOT)/gem_suppl
  ifeq ($(BUILD_SUPPL),y)
    ALL_TARGETS += $(SUPPL_TARGET)
  endif
endif
ifeq ($(SUPPL),WPA)
  SUPPL_TARGET = $(OUTPUT_DIR)/wpa_supplicant
  TI_SUPP_LIB_DIR = $(CUDK_ROOT)/wpa_suppl
  ifeq ($(BUILD_SUPPL),y)
    ALL_TARGETS += $(SUPPL_TARGET)
  endif
endif

ifeq ($(SUPPL),DEVICESCAPE)
  SUPPL_TARGET = $(OUTPUT_DIR)/wpa_supplicant
  TI_SUPP_LIB_DIR = $(CUDK_ROOT)/devicescape-dsa-XCC-wps-2.0.1-008
  ifeq ($(BUILD_SUPPL),y)
    ALL_TARGETS += $(SUPPL_TARGET)
  endif
endif



ifeq ($(TI_HOST_OS),ANDROID)
	LDFLAGS += --static
endif

.PHONY: all
#MOTO
all: 
	echo ignore
all: $(ALL_TARGETS)

.PHONY: $(SUPPL_TARGET)
$(SUPPL_TARGET):
ifeq ($(SUPPL),DEVICESCAPE)
	$(MAKE) -e -C $(TI_SUPP_LIB_DIR) DEBUG=$(DEBUG) XCC=$(XCC) CROSS_COMPILE=$(CROSS_COMPILE) STATIC_LIB=$(STATIC_LIB) TI_WLAN_DRIVER=y CONFIG_CTRL_IFACE=unix CONFIG_EAP_WSC=y CONFIG_WPS=y LDFLAGS=$(LDFLAGS)
endif

ifeq ($(SUPPL),WPA)
	$(MAKE) -e -C $(TI_SUPP_LIB_DIR) DEBUG=$(DEBUG) XCC=$(XCC) CROSS_COMPILE=$(CROSS_COMPILE) STATIC_LIB=$(STATIC_LIB) TI_WLAN_DRIVER=y CONFIG_CTRL_IFACE=unix CONFIG_EAP_WSC=y CONFIG_WPS=y
endif

ifeq ($(SUPPL),GEM)
	$(MAKE) -e -C $(TI_SUPP_LIB_DIR) DEBUG=$(DEBUG) XCC=$(XCC) CROSS_COMPILE=$(CROSS_COMPILE) STATIC_LIB=$(STATIC_LIB) TI_WLAN_DRIVER=y CONFIG_CTRL_IFACE=unix CONFIG_EAP_WSC=$(CONFIG_EAP_WSC) CONFIG_WPS=y LDFLAGS=$(LDFLAGS)

endif
#	$(CROSS_COMPILE)strip -s $(TI_SUPP_LIB_DIR)/wpa_supplicant
#	cp -f $(TI_SUPP_LIB_DIR)/wpa_supplicant $(OUTPUT_DIR)

.PHONY: $(OS_TARGET)
$(OS_TARGET):
	@echo ALL_TARGETS=$(ALL_TARGETS)
	@echo SUPPL=$(SUPPL)
	@echo BUILD_SUPPL=$(BUILD_SUPPL) 
	@echo TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR)
	$(MAKE) -C $(TI_OS_LIB_DIR) CROSS_COMPILE=$(CROSS_COMPILE) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB) XCC=$(XCC) WPA_ENTERPRISE=$(WPA_ENTERPRISE) SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL) TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR) ETH_SUPPORT=$(ETH_SUPPORT)

.PHONY: $(CU_TARGET)
$(CU_TARGET):
	$(MAKE) -C $(CU_DIR) CROSS_COMPILE=$(CROSS_COMPILE) TI_HOSTAPD_LIB=$(TI_HOSTAPD_LIB) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB) XCC=$(XCC) WPA_ENTERPRISE=$(WPA_ENTERPRISE) SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL) TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR)

#$(MAKE) -C $(CU_DIR) CROSS_COMPILE=$(CROSS_COMPILE) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB) XCC=$(XCC) WPA_ENTERPRISE=$(WPA_ENTERPRISE) SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL) TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR)
#$(MAKE) -C $(CU_DIR) CROSS_COMPILE=$(CROSS_COMPILE) TI_HOSTAPD_LIB=$(TI_HOSTAPD_LIB) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB) XCC=$(XCC) WPA_ENTERPRISE=$(WPA_ENTERPRISE) SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL) TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR)

.PHONY: $(LOGGER_TARGET)
$(LOGGER_TARGET):
	$(MAKE) -C $(LOGGER_DIR) CROSS_COMPILE=$(CROSS_COMPILE) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB) XCC=$(XCC) WPA_ENTERPRISE=$(WPA_ENTERPRISE) SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL) TI_SUPP_LIB_DIR=$(TI_SUPP_LIB_DIR) ETH_SUPPORT=$(ETH_SUPPORT)


.PHONY: $(LOADER_TARGET)
$(LOADER_TARGET):
	$(MAKE) -C $(WLAN_LOADER_DIR) CROSS_COMPILE=$(CROSS_COMPILE) DEBUG=$(DEBUG) STATIC_LIB=$(STATIC_LIB)

.PHONY: $(TI_HOSTAPD_TARGET)
$(TI_HOSTAPD_TARGET):
	$(MAKE) -C $(TI_HOSTAPD_DIR) TI_HOSTAPD_LIB=$(TI_HOSTAPD_LIB)

.PHONY: clean
clean:
	@echo SUPPL=$(SUPPL) BUILD_SUPPL=$(BUILD_SUPPL)
	$(MAKE) -C $(CU_DIR) CROSS_COMPILE=$(CROSS_COMPILE) BUILD_SUPPL=$(BUILD_SUPPL) XCC=$(XCC) clean
	$(MAKE) -C $(LOGGER_DIR) CROSS_COMPILE=$(CROSS_COMPILE) BUILD_SUPPL=$(BUILD_SUPPL) XCC=$(XCC) ETH_SUPPORT=$(ETH_SUPPORT) clean
	$(MAKE) -C $(TI_OS_LIB_DIR) CROSS_COMPILE=$(CROSS_COMPILE) BUILD_SUPPL=$(BUILD_SUPPL) XCC=$(XCC) ETH_SUPPORT=$(ETH_SUPPORT) clean
	$(MAKE) -C $(WLAN_LOADER_DIR) CROSS_COMPILE=$(CROSS_COMPILE) clean
	$(MAKE) -C $(TI_HOSTAPD_DIR) clean

ifeq ($(BUILD_SUPPL), y)
	rm -f $(OUTPUT_DIR)/wpa_supplicant
ifeq ($(SUPPL),)
	$(MAKE) -e -C $(CUDK_ROOT)/gem_suppl CROSS_COMPILE=$(CROSS_COMPILE) clean
	$(MAKE) -e -C $(CUDK_ROOT)/wpa_suppl CROSS_COMPILE=$(CROSS_COMPILE) clean
	$(MAKE) -e -C $(CUDK_ROOT)/devicescape-dsa-XCC-wps-2.0.1-008 CROSS_COMPILE=$(CROSS_COMPILE) clean
else
	$(MAKE) -C $(TI_SUPP_LIB_DIR) CROSS_COMPILE=$(CROSS_COMPILE) BUILD_SUPPL=$(BUILD_SUPPL) XCC=$(XCC) clean
endif
endif

