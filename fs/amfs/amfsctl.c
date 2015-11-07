#include "amfsctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
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
	int list_flag = 0;
	char *pattern = NULL;
	char delimeter = '\n';
	/* Operations
	 * List: 0
	 * Add: 1
	 * Remove: 2
	 */
	int operation = -1;
//	char* buffer = NULL;
	while((c = getopt(argc, argv, "la:r:"))!=-1){
		switch(c){
			case 'l':
				if(flag){
					errno = -EINVAL;
					fprintf(stderr," More than one argument passed\n");
					goto error;
				}
				flag = 1;
				list_flag = 1;
				code = AMFSCTL_READ_PATTERN;
				operation = 0;	
				//command = "AMFSCTL_READ_PATTERN";	
				option = (char*)malloc(4096);
				break;
			case 'a':
				if(flag){
					errno = -EINVAL;
					fprintf(stderr," More than one arguments are passed\n");
					goto error;
				}
				flag = 1;
				operation = 1;
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
				operation = 2;
				code = AMFSCTL_REMOVE_PATTERN;
				option = optarg;
			//	command = "AMFSCTL_REMOVE_PATTERN";
				break;
			case '?':
				errno = -EINVAL;
				code = 4;
				fprintf(stderr,"Invalid argument passed\n");
				printf("Usage ./amfsctl flag parameter mount point\n");
				printf("Flags\n");
				printf("-a to add pattern \n");
				printf("-r to remove pattern\n");
				printf("-l to list pattern\n");
				break;
		}
	}
	if(code == -1){
		errno = -EINVAL;
		fprintf(stderr,"Missing flags\n");
		printf("Usage: ./amfsctl flag option mount point\n");
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
		switch(operation){
		case 0:
			printf("Failed to list patterns\n");
			break;
		case 1:
			printf("Pattern exists. Duplicate not added to list\n");
			break;
		case 2:
			printf("Pattern doesn't exist. Nothing done\n");
			break;
		default:
			perror("ERROR:");
		}
	}
	if(list_flag){
		printf("%s",option);
		free(option);
	}
		
	close(fd);	
	error: return errno;
		
}	
