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
	char* input_file;
	char* output_file;
	char* key;
	int keylength;
	int flags;
}((__attribute_packed__));
/**********Structutr defination ends here************************/
	
int main(int argc,char* argv[])
{
	int rc;
	/****CODE TO CREATE A STRUCTURE OBJECT AND FILL IT*********/
	
	struct input_data argument;
	void *dummy = (void *)&argument;
	size_t length = 0;
	int option = 0;
	int flag_encrypt = 0;
	int flag_decrypt = 0;
	//int optind = -1;
	//printf("Entering while loop");
	while((option = getopt(argc,argv,"p:edh"))!=-1){
		switch(option){
			case 'p':
				length = strlen(optarg)+1;
				argument.key = malloc(length);
				memcpy(argument.key,optarg,length);
				if(argument.key[0] == '-' && (argument.key[1]=='e' || argument.key[1]=='d')){
					fprintf(stderr,"Argument is reqguired for password");
					return 1;
				}
				//printf("Printing %s",argument.key);
				break;
			case 'e':
				flag_encrypt = 1;
				break;
			case 'd':
				flag_decrypt = 1;
				break;
			case 'h':
				printf("Usage Message: \n\t This command takes 4 arguments -p is the Passphrase -e to encrypt or -d to decrypt infile and outfile \n Usage Example ./xcipher -p \"This is PassPhrase\" -e inputfile outputfile");
				return 0;
			case '?':
				if(optopt == 'p'){
					fprintf(stderr,"Option -%c is missing argument.\n",optopt);
					return 1;
				}
				else{
					fprintf(stderr,"Unknown Argument, to know usagae type ./xcipher -h");
					return 1;
				}
				break;
			default: break;
		}
				
	}
	 
	
	length = strlen(argv[optind])+1;
	argument.input_file = malloc(length);
	memcpy(argument.input_file,argv[optind++],length);

	length = strlen(argv[optind])+1;
	argument.output_file = malloc(length);
	memcpy(argument.output_file,argv[optind++],length);
	argument.keylength = strlen(argument.key);
	if(flag_encrypt && flag_decrypt){
		fprintf(stderr,"You cannot pass both encrypt and decrypt flag");
		return 1;
	}
	if(flag_encrypt)
		argument.flags = 1;
	if(flag_decrypt)
		argument.flags = 0;
	printf("Printing struct values \n input file %s \noutput file %s \npassphrase %s \n flags %d \n keylegth %d\n",argument.input_file, argument.output_file, argument.key,argument.flags,argument.keylength);
	/****CODE OF STRUCTURE FILLING END HERE********/

//	void *dummy = (void *) argv[1];

  	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}
