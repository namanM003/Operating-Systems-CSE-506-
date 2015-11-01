#include "amfsctl.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
int main(){
	char *test = "Test this IOCTL";
	int fd = open("/mnt/amfs",O_RDONLY);
	if(ioctl(fd,AMFSCTL_READ_PATTERN, test)==-1){
		perror("Erroe:");
	}
}	
