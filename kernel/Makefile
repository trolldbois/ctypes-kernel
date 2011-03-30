#!/bin/sh


build=`uname -r`
#KHEADERS="/usr/src/linux-headers-2.6.35-28/"
KHEADERS="/usr/src/linux-headers-$build/"
ARCHINC="$KHEADERS/arch/x86/include"

all:
	gcc -std=c++98 -x c++ ctypes_linux.c -P -E   -nostdinc  -D __KERNEL__  -I$ARCHINC -I$KHEADERS/include  -include $KHEADERS/include/generated/autoconf.h -isystem /usr/lib/gcc/i686-linux-gnu/4.4.5/include -I/usr/src/linux-headers-lbm-  -Wall -Wundef -Wno-trigraphs -fno-strict-aliasing -fno-common  -Wno-format-security -fno-delete-null-pointer-checks -O2 -m32 -msoft-float -mregparm=3 -freg-struct-return -mpreferred-stack-boundary=2 -march=i686 -mtune=generic -maccumulate-outgoing-args -ffreestanding -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -Wno-sign-compare -fno-asynchronous-unwind-tables   -o ctypes_linux_generated.c && echo "GENERATED ctypes_linux_generated.c - please correct source code gccxml is gonna choke on kernel source code"
	gccxml ctypes_linux_generated.c -fxml=ctypes_linux_generated.xml -fextended-identifiers -fpreprocessed
	#gccxml ctypes_linux_generated.c -fxml=ctypes_linux_generated.xml && echo "GENERATED ctypes_linux_generated.xml" \
	#  && xml2py ctypes_linux_generated.xml -o ctypes_linux_generated.py -k d -k e -k s -k t && echo "GENERATED ctypes_linux_generated.py - DONE"

clean:
	rm -f ctypes_linux_generated.xml ctypes_linux_generated.py ctypes_linux_generated_clean.c ctypes_linux_generated.c ctypes_linux_generated.pyc



