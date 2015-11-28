
struct job_metadata {
	int type; /* Store type of job to be performed*/
	char* input_file;
	char* output_file;
	char* key;
	int no_of_files; /* this variable will store the number of files*/
}((__attribute_packed__));

struct job_queue {
	struct list_head job_q;	/*Queue to hold jobs */
	struct job_metadata job_d; /* Jon specific data */
}
