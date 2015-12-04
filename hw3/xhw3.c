#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <pthread.h>
#include "job_metadata.h"
#include "netlink.h"
#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

int main(int argc,char* argv[])
{
	int rc;
	int pid;
	pthread_t thread;
	/****Variable Declarations start here*********/
	/* Job Defination Flags
	 * 1 to Encrypt/Decrypt
	 * 2 Compression/Decompression
	 * 3 For hashing
	 * 4 to list all jobs
	 * 5 to remove a job
	 * 6 to change priority
	 */
	/*
	 * Other Flags
	 * -t type
	 * -i input file //NOT USING
	 * -o output file //NOT USING
	 * -e/-d to encrypt/decrypt
	 * -c/-z to compress/decompress
	 * -j job id
	 * -k key
	 * -p new priority
	 * -a algorihtm //Will support 1 by default for each
	 * -x Delete original file
	 * -w overwrite
	 * -r rename
	 */
	struct job_metadata argument;
	void *dummy = (void *)&argument;
	//size_t length = 0;
	int option = 0;
	/* This flag will be used to in both cases encrypt/decrypt on
	 * compression/decompression*/
	int flag_encrypt = 0;
	int flag_decrypt = 0;
	int flag_compress = 0;
	int flag_decompress = 0;
	int rename = 0;
	int overwrite = 0;
	int delete = 0;
	int algorithm = 0;
	int key = 0;
	int type = 0;
	int job_priority = 0;
	int error = 0;
	unsigned int job_id = 0;
	char *realpath_f = NULL;
	/**********Variable Declarations end  here**********/

	/*unsigned char* hash = malloc(SHA_DIGEST_LENGTH);*/
	memset(&argument,0,sizeof(struct job_metadata));

	/*
	 * argument.keybuf = malloc(SHA_DIGEST_LENGTH+1);
	 * memset(argument.keybuf,0,SHA_DIGEST_LENGTH+1);
	 */
	argument.job_priority = 5;
	argument.input_file = NULL;
	argument.output_file = NULL;

	while ((option = getopt(argc,argv,"a:t:k:edczj:p:xwrh")) != -1) {
		switch(option){
		case 'a':
			algorithm = 1;
			argument.algorithm = malloc(strlen(optarg)+1);
			memset(argument.algorithm, 0, strlen(optarg)+1);
			memcpy(argument.algorithm, optarg, strlen(optarg)+1);
			break;
		case 't':
			argument.type = atoi(optarg);
			type = atoi(optarg);
			break;
		case 'k':
			key = 1;
			if (strlen(optarg) < 6) {
				//printf("Key size too small\n");
				key = 2;
			}
			argument.key = malloc(strlen(optarg)+1);
			memset(argument.key, 0, strlen(optarg)+1);
			memcpy(argument.key, optarg, strlen(optarg)+1);
			break;
		case 'e':
			flag_encrypt = 1;
			argument.operation = 1;
			break;
		case 'd':
			flag_decrypt = 1;
			argument.operation = 2;
			break;
		case 'c':
			flag_compress = 1;
			argument.operation = 1;
			break;
		case 'z':
			flag_decompress = 1;
			argument.operation = 2;
			break;
		case 'j':
			argument.jobid = atoi(optarg);
			job_id = atoi(optarg);
			break;
		case 'p':
			argument.job_priority = atoi(optarg);
			job_priority = atoi(optarg);
			break;
		case 'x':
			delete = 1;
			argument.delete_f = 1;
			break;
		case 'w':
			overwrite = 1;
			argument.overwrite = 1;
			break;
		case 'r':
			rename = 1;
			argument.rename = 1;
			break;
		case 'h':
			/* Correct this usage message */
			printf("Usage:\n");
			printf("To Encrypt/Decrypt\n");
			printf("\t./xsubmit -t 1 -e/-d -a \"algo name\" -k"
				       " \"key\" inputfile outputfile\n"
				"Optional flags:\n\t-x to delete input file\n"
				"\t-r to rename\n \t-w to overwrite\n");
			printf("\tAlgorithms Supported\n\t");
			printf("\t 1. aes \n\t\t 2. blowfish \n\t\t 3. des\n");
			printf("To find checksum\n");
			printf("\t./xsubmit -t 3 -a \"algo name\" inputfile\n");
			printf("\tAlgorithms Supported\n");
			printf("\t\t 1. md5\n\t\t 3. sha1\n");
			printf("To list jobs\n");
			printf("\t./xsubmit -t 4\n");
			printf("To remove a job\n");
			printf("\t./xsubmit -t 5 -j jobid\n");
			printf("To change priority\n");
			printf("\t./xsubmit -t 6 -j jobid -p new priority\n"
				"Priority supported between 1-10. 10 being "
				"highest.\n");

			return 0;
		case '?':
			if (optopt == 'p' || optopt == 'a' || optopt == 't' ||
					optopt == 'j' || optopt == 'k') {
				fprintf(stderr,"Option -%c is missing"
					       " argument.\n",optopt);
				goto out;
			} else {
				fprintf(stderr,"Unknown Argument, to know "
					       "usage type ./xsubmit -h\n");
				goto out;
			}
			break;
		default: break;
		}
	}
	if (optind < argc) {
		realpath_f = realpath(argv[optind], NULL);
		optind++;
		if (realpath_f != NULL) {
			argument.input_file = malloc(strlen(realpath_f)+1);
			memset(argument.input_file, 0, strlen(realpath_f)+1);
			memcpy(argument.input_file, realpath_f,
					strlen(realpath_f));
			free(realpath_f);
			printf("%s\n",argument.input_file);
		}
		realpath_f = NULL;
	}
	
	if (optind < argc) {
		realpath_f = realpath(argv[optind], NULL);
		optind++;
		if (realpath_f != NULL) {
			argument.output_file = malloc(strlen(realpath_f)+1);
			memset(argument.output_file, 0, strlen(realpath_f)+1);
			memcpy(argument.output_file, realpath_f, strlen(realpath_f));
			free(realpath_f);
			printf("%s\n", argument.output_file);
		} else {
			argument.output_file = malloc(strlen(argv[--optind])+1);
			memset(argument.output_file, 0, strlen(argv[optind])+1);
			memcpy(argument.output_file, argv[optind], strlen(argv[optind]));
		}
		realpath_f = NULL;
		
	}

	if (type == 0) {
		printf("Missing type cannot judge which job to run\n");
		error = -EINVAL;
		goto out;
	}
	switch(type) {
		case 1:
			/* This is the encrypt decrypt job
			 * Mandatory Requirements
			 * -a: Algorithm
			 * -e/-d : Encrypt or Decrypt
			 * -p: Optional
			 * -k : Key
			 */
			if ( !algorithm || !(flag_encrypt || flag_decrypt) || !key) {
				printf("Missing 1 or more mandatory argument");
				error = -EINVAL;
				goto out;
			}
			if (key == 2) {
				printf("Key length too small\n");
				error = -EINVAL;
				goto out;
			}

			if ( strcmp("aes", argument.algorithm) &&
				strcmp("blowfish", argument.algorithm) &&
				strcmp("des", argument.algorithm) ) {
				printf("Unsupported algorithm passed\n");
				error = -EINVAL;
				goto out;
			}
			if ( flag_compress || flag_decompress || (flag_encrypt
				&& flag_decrypt) || job_id || ((delete &&
				overwrite) || (delete && rename) ||
					(overwrite && rename))) {
				printf("One or more wrong/extra argument sent\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.input_file) {
				printf("Input file is missing\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.output_file && !(rename || overwrite || delete)) {
				printf("Missing output file name\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.output_file) {
				argument.output_file = malloc
					(strlen(argument.input_file)+1);
				strcpy(argument.output_file,
						argument.input_file);
			}
			break;
		case 2:
			/* This is compress decompress job */
			if (!algorithm || !(flag_compress || flag_decompress)) {
			       printf("Missing 1 or more mandatory parameter"
					      "  to compress or decompress\n");
			       error = -EINVAL;
			       goto out;
			}
			if ( job_id || flag_encrypt || flag_decrypt ||
				((flag_compress && flag_decompress)) ||
				((delete && overwrite) || (delete && rename)
				|| (overwrite && rename))) {
				printf("One or more wrong/extra "
						"arguments passed\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.input_file) {
				printf("Input file name is missing\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.output_file &&
					!(rename || overwrite || delete)) {
				printf(" Missing output file name\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.output_file) {
				argument.output_file = malloc
					(strlen(argument.input_file)+1);
				strcpy(argument.output_file,
						argument.input_file);
			}
			printf("Operation not implemented correctly,"
				       " hence removed\n");
			goto out;
			break;
		case 3:
			if (!algorithm) {
				printf("Algorithm name missing\n");
				error = -EINVAL;
				goto out;
			}
			if ( flag_compress || flag_decompress || flag_encrypt
				|| flag_decrypt || job_id || delete
				|| overwrite || rename) {
				printf("One or more unwanted arguments"
					       " passed\n");
				error = -EINVAL;
				goto out;
			}
			if (!argument.input_file) {
				printf("Missing input file name\n");
				error = -EINVAL;
				goto out;
			}
			if (strcmp("md5", argument.algorithm) && strcmp("sha1"
						, argument.algorithm)) {
				printf("Unsupported Algorithm passed. "
					"Currently we support sha1 and md5\n");
				error = -EINVAL;
				goto out;
			}	
			break;
		case 4:
			if (algorithm || flag_encrypt || flag_decrypt ||
				flag_compress || rename || overwrite || delete
			       || key || job_priority || job_id ) {
				printf("Extra invalid arguments passed\n");
				error = -EINVAL;
				goto out;
			}
			argument.algorithm = malloc(4096);
			memset(argument.algorithm, 0, 4096);
			break;
		case 5:
			if (!job_id || job_id <= 0) {
				printf("Missing Job ID or incorrect job id "
					       "(Should be greater than 0)\n");
				error = -EINVAL;
				goto out;
			}
			if (algorithm || flag_encrypt || flag_decrypt ||
				flag_compress || rename || overwrite ||
			       	delete || key || job_priority) {
				printf("Invalid flag passed\n");
				error = -EINVAL;
				goto out;
			}
			argument.algorithm = malloc(4096);
			memset(argument.algorithm, 0, 4096);
			break;
		case 6:
			if (!job_id || !job_priority || job_priority < 1
					|| job_priority > 10) {
				printf("Missing/Invalid job id or job "
					       "priority\n");
				error = -EINVAL;
				goto out;
			}
			if (algorithm || flag_encrypt || flag_decrypt ||
				flag_compress || rename || overwrite || delete
					|| key) {
				printf("Invalid parameters passed.\n");
				error = -EINVAL;
				goto out;
			}
			argument.algorithm = malloc(4096);
			memset(argument.algorithm, 0, 4096);
			break;
		case 7:
			printf("Sorry this functionality is not yet "
					"implemented\n");
			goto out;
		default:
			printf("Invalid Option \n");
			error = -EINVAL;
			goto out;
	}

	pid = getpid();
	argument.pid = pid;
	/***********Create Socket only for jobs not remove priority and list
	 */
	if (type == 1 || type ==2 || type == 3) {
		createSocket(pid);
		pthread_create(&thread, NULL, (void *) &listen_to_kernel,
				(void*)pid);
	}
	rc = syscall(__NR_submitjob, dummy, 3);
	if (rc == 0) {
		printf("syscall returned %d\n ",rc);
		//printf(" Job Successfully registered\n");
		switch (type) {
		case 4:
			printf("Job ID\t Job type\n");
			printf("%s\n",argument.algorithm);
			printf(" *Legend \n Type:\n 1. Encrypt/Decrypt"
				"\n 2. Compress/Decompress \n "
				"3. Hashing\n");
			break;
		case 5:
			printf("%s\n",argument.algorithm);
			break;
		case 6:
			printf("%s\n",argument.algorithm);
			break;
		default:
			printf("Job successfully registered\n");
			break;
		}
		//free(argument.algorithm);
		if (type == 4 || type ==5 || type == 6) {
			free(argument.algorithm);
			goto out;
		}
	}
	else {
		perror("ERROR:");
	}
	
	while (1) {
		printf("Yo--");
		printf("Main Thread running \n");
		while(1) {
			continue;
		}
	}
	

out:
	return error;
}
