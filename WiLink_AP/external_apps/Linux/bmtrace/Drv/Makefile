
PWD := $(shell pwd)
WILINK_ROOT = ../../../..

TRACE ?= n
STRIP = n

EXTRA_CFLAGS =  -I$(KERNEL_DIR) -I$(PWD)/$(WILINK_ROOT)/utils  


ifeq ($(KERNEL_DEBUGGER),y)
  EXTRA_CFLAGS += -g -O2
endif	
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -DBM_DEBUG -O2
else
  EXTRA_CFLAGS += -O2
  STRIP = y
endif	

ifneq ($(KERNELRELEASE),)

obj-m := bmtrace.o

else

all:
	@echo EXTRA_CFLAGS = $(EXTRA_CFLAGS)
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" -C $(KERNEL_DIR)  M=$(PWD) modules

ifeq ($(STRIP),y)
	@echo $(CROSS_COMPILE)strip -g bmtrace.ko
	$(CROSS_COMPILE)strip -g bmtrace.ko
endif

endif

clean:
	rm -f *.o *~ *.~* core .depend dep
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

help:
	echo CROSS_COMPILE=$(CROSS_COMPILE) 
	echo KERNEL_DIR=$(KERNEL_DIR)
	echo EXTRA_CFLAGS=$(EXTRA_CFLAGS)
