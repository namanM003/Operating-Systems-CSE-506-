obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xsubmitjob xsubmit

xsubmit: xhw3.c
		gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw3.c -lssl -o xsubmit

xsubmitjob:
		make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
		rm -f xsubmit
