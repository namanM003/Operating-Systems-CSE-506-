#include "amfsctl.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <error.h>
int main(int argc, char **argv){
	int err = 0;
	int c;
	int flag = 0;
	while((c = getopt(argc, argv, "la:r:"))
	char *test = "Test this IOCTL";
	int fd = open("/mnt/amfs",O_RDONLY);
	if(ioctl(fd,AMFSCTL_READ_PATTERN, test)==-1){
		perror("Erroe:");
	}
}	
