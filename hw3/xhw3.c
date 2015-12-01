#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "job_metadata.h"
#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

int main(int argc,char* argv[])
{
	int rc;
	/****Variable Declarations start here*********/
	//struct stat stat_data;
	//struct stat output_file_stat;	
	struct job_metadata argument;
	void *dummy = (void *)&argument;
	//size_t length = 0;
	int option = 0;
	int flag_encrypt = 0;
	int flag_decrypt = 0;
	/**********Variable Declarations end  here**********/

	/*unsigned char* hash = malloc(SHA_DIGEST_LENGTH);*/
	memset(&argument,0,sizeof(struct job_metadata));

	/*
	 * argument.keybuf = malloc(SHA_DIGEST_LENGTH+1);
	 * memset(argument.keybuf,0,SHA_DIGEST_LENGTH+1);
	 */

	while ((option = getopt(argc,argv,"p:edh"))!=-1) {
		switch(option){
		case 'p':
			if(strlen(optarg) < 6){
				errno = EINVAL;
				fprintf(stderr,"Keylength should be atleast"
					" 6 characters long. Exiting\n");
				goto out;
			}
			/*
			 * SHA1((unsigned char*)optarg,strlen(optarg),hash);
			 */
			argument.key = malloc(strlen(optarg)+1);
			memcpy(argument.key, optarg, strlen(optarg)+1);
			break;
		case 'e':
			flag_encrypt = 1;
			break;
		case 'd':
			flag_decrypt = 1;
			break;
		case 'h':
			printf("Usage Message: \n\t This command takes 4 "
				"arguments -p is the Passphrase -e to encrypt "
			       "or -d to decrypt infile and outfile \n Usage "
			      " Example ./xcipher -p \"This is PassPhrase\" -e"
			     " inputfile outputfile\n");
			return 0;
		case '?':
			if (optopt == 'p') {
				fprintf(stderr,"Option -%c is missing"
					       " argument.\n",optopt);
				goto out;
			} else {
				fprintf(stderr,"Unknown Argument, to know "
					       "usage type ./xcipher -h\n");
				goto out;
			}
			break;
		default: break;
		}
	}
	argument.input_file = malloc(6);
	argument.output_file = malloc(6);
	argument.type = 5;
	argument.job_priority = 5;
	argument.algorithm = malloc(4096);
	//argument.job_id = 10;
	memset(argument.input_file, 0, 6);
	memset(argument.output_file, 0, 6);
	memcpy(argument.input_file, "file1", 5);
	memcpy(argument.output_file, "file2", 5);
	/*
	 * Rectify 3 with argslen
	 */
	rc = syscall(__NR_submitjob, dummy, 3);
	if (rc == 0) {
		printf("syscall returned %d\n ",rc);
		if (flag_encrypt) {
			printf("Encryption Successful\n");
		}
		if (flag_decrypt) {
			printf("Decryption Successful\n");
		}
		printf(argument.algorithm);
	}
	else {
		perror("ERROR:");
	}


out:
	return 0;
}
