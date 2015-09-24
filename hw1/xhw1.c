#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
/**********Defination of structure that will hold user input data***************/
struct input_data{
	char input_file[50];
	char output_file[50];
	char key[50];
	int keylength;
	int flags;
}((__attribute_packed__));
/**********Structutr defination ends here************************/
	
int main(int argc, const char *argv[])
{
	int rc;
	/****CODE TO CREATE A STRUCTURE OBJECT AND FILL IT*********/
	struct input_data input;
	void *dummy = (void *)&input;
	//input.input_file = malloc(sizeof(argv[1]));
	strcpy(input.input_file,argv[1]);
	strcpy(input.output_file,argv[2]);
	strcpy(input.key,argv[3]);
	input.keylength = sizeof(input.key);
	input.flags = atoi(argv[4]);
	printf("Printing %d\n",input.flags);
	/****CODE OF STRUCTURE FILLING END HERE********/

//	void *dummy = (void *) argv[1];

  	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}
