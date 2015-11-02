#include "amfsctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
int main(int argc, char **argv){
	errno = 0;
	int c;
	int flag = 0;
	char* option = NULL;
	//extern char *optarg;
	//extern int optind;
	//char* command = NULL;
	char* file = NULL;
	int code = -1;
	printf("Before while loop\n");
	while((c = getopt(argc, argv, "la:r:"))!=-1){
		switch(c){
			case 'l':
				if(flag){
					errno = -EINVAL;
					fprintf(stderr," More than one argument passed\n");
					goto error;
				}
				flag = 1;
				code = AMFSCTL_READ_PATTERN; 
				//command = "AMFSCTL_READ_PATTERN";	
//				option = malloc(4096);
				break;
			case 'a':
				if(flag){
					errno = -EINVAL;
					fprintf(stderr," More than one arguments are passed\n");
					goto error;
				}
				flag = 1;
				code = AMFSCTL_ADD_PATTERN;
				option = optarg;
			//	commnand = "AMFSCTL_ADD_PATTERN";
				break;
			case 'r':
				if(flag){
					errno = -EINVAL;
					fprintf(stderr,"More than one arguments passed\n");
					goto error;
				}
				flag = 1;
				code = AMFSCTL_REMOVE_PATTERN;
				option = optarg;
			//	command = "AMFSCTL_REMOVE_PATTERN";
				break;
			case '?':
				errno = -EINVAL;
				code = -1;
				fprintf(stderr,"Invalid argument passed\n");
				break;
		}
	}
	printf("After while loop\n");
	printf("%s %s arguments\n",argv[optind], option);
	if(code == -1){
		errno = -EINVAL;
		fprintf(stderr,"Missing flag\n");
		goto error;
	}
	if(optind == argc){
		errno = -EINVAL;
		fprintf(stderr,"Missing device name\n");
		goto error;
	}
	file = argv[optind];
	//char *test = "Test this IOCTL";
	int fd = open(file,O_RDONLY);
	if(fd <= 0){
		fprintf(stderr,  "Incorrect device name\n");
		errno = -EINVAL;
		goto error;
	}
	if(ioctl(fd,code,option)==-1){
		perror("Error: IOCTL");

	}
	
	error: return errno;
		
}	
