obj-m += module.o
KDIR := /home/salahuddin/nexus5/nexus5_org_kernel
CC_PATH := /home/salahuddin/nexus5/nexus5_org_kernel/arm-eabi-4.6/bin

-include version.mk

all: dwarf
dwarf: module.c
	$(MAKE) ARCH=arm CROSS_COMPILE=$(CC_PATH)/arm-eabi- -C $(KDIR) CONFIG_DEBUG_INFO=y M=$(PWD) modules
	dwarfdump -di module.ko > module.dwarf

clean:
	$(MAKE) -C $(KDIR)/lib/modules/$(KVER)/build M=$(PWD) clean
	rm -f module.dwarf
