#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "input_data.h"
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
	
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
	memset(&argument,0,sizeof(struct input_data));
	printf("No of arguments %d\n\n",argc);
	while((option = getopt(argc,argv,"p:edh"))!=-1){
		switch(option){
			case 'p':
				length = strlen(optarg)+1;
				argument.keybuf = malloc(length);
				memcpy(argument.keybuf,optarg,length);
				if(argument.keybuf[0] == '-' && (argument.keybuf[1]=='e' || argument.keybuf[1]=='d')){
					fprintf(stderr,"Argument is reqguired for password\n");
					goto FREEBUF;
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
				printf("Usage Message: \n\t This command takes 4 arguments -p is the Passphrase -e to encrypt or -d to decrypt infile and outfile \n Usage Example ./xcipher -p \"This is PassPhrase\" -e inputfile outputfile\n");
				return 0;
			case '?':
				if(optopt == 'p'){
					fprintf(stderr,"Option -%c is missing argument.\n",optopt);
					goto FREEBUF;
				}
				else{
					fprintf(stderr,"Unknown Argument, to know usage type ./xcipher -h\n");
					goto FREEBUF;
				}
				break;
			default: break;
		}
				
	}
	
	 if(flag_encrypt && flag_decrypt){
                fprintf(stderr,"You cannot pass both encrypt and decrypt flag");
                goto FREEBUF;
        }
        if(!flag_encrypt && !flag_decrypt){
                fprintf(stderr,"Missing Flag: Forgot to pass whether to encrypt (-e) or decrypt (-d)\n");
                goto FREEBUF;
        }


	printf("Current optind index %d\n\n\n",optind);
	
	if(optind >= argc){
		fprintf(stderr,"Missing input file argument\n");
		goto FREEBUF;
	}
	length = strlen(argv[optind])+1;
	argument.input_file = malloc(length);
	memcpy(argument.input_file,argv[optind++],length);
	
	if(optind >= argc){
		fprintf(stderr,"Missing output file argument\n");
		goto FREEIN;
	}
	length = strlen(argv[optind])+1;
	argument.output_file = malloc(length);
	memcpy(argument.output_file,argv[optind++],length);
	argument.keylen = strlen(argument.keybuf);
	
	if(flag_encrypt)
		argument.flags = 1;
	if(flag_decrypt)
		argument.flags = 0;
	//DEBUG MESSAGE COMMENT BEFORE SUBMITTING
	printf("Printing struct values \n input file %s \noutput file %s \npassphrase %s \n flags %d \n keylegth %d\n",argument.input_file, argument.output_file, argument.keybuf,argument.flags,argument.keylen);
	/****CODE OF STRUCTURE FILLING END HERE********/
	/******CODE TO CHECK WHETHER USER HAS READ PERMISSION ON FILE OR NOT*********/
//	FILE* file_id=NULL;
	if(access(argument.input_file,F_OK)){
		fprintf(stderr,"File doesn't exist. Please give a valid file name\n");
		goto FREEOUT;
		}
	if(access(argument.input_file,R_OK)){
		fprintf(stderr,"You don't have permission to read file. Exiting\n");
		goto FREEOUT;
	}
	if(!access(argument.output_file,F_OK)){
		if(access(argument.output_file,W_OK)){
			fprintf(stderr,"Output file exists to which you dont have write rights\n");
			goto FREEOUT;
		}
	}
	

  	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0){
		//printf("syscall returned %d\n", rc);
	}
	else
		perror("ERROR:");
	
	FREEOUT: free(argument.output_file);
	FREEIN:	 free(argument.input_file);
	FREEBUF: free(argument.keybuf);

	exit(rc);
}
