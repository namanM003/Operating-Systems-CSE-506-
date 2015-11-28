#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include "job_metadata.h"
#define MAX 128

 asmlinkage extern long (*sysptr)(void *arg, int argslen);
/*
 * struct workqueue_struct *hw3_assigment = NULL;
 */

struct job_queue *jobs = NULL;
struct job_queue *job = NULL;

asmlinkage long submitjob(void *arg, int argslen)
{	
	int counter = 0;
	int error = 0;
	struct job_queue *head = NULL;
	struct job_queue *next_job  = NULL;
	head = jobs;
	list_for_each_entry(next_job, &jobs->job_q, job_q) {
		counter = counter + 1;
	}
	if (counter >= MAX) {
		printk("Error: Queue is full\n");
		error = -EAGAIN;
		goto out;
	}
	job = NULL;
	if (!access_ok(VERIFY_READ, arg, sizeof(job_metadata))) {
		error = -EACCES;
		goto out;
	}
	job = (struct job_queue *)kzalloc(sizeof(struct job_queue),
		       	__GFP_WAIT);
	if (job == NULL) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(job->job_d, (struct job_metadata *)arg,
			       	sizeof(struct job_metadata))) {
		error = -EFAULT;
		goto out_free;
	}
	
	/* Type and their description
	 * Type 1: Encrypt decrypt the file
	 * Type 2: Compress/Decompress file
	 * Type 3 Compute Checksum
	 * Type 4: Concatenate File
	 */
	switch(job->job_d.type) {
	
		case 1:
			/* Type 1 is for encrypting a file */
			job->job_d->input_file = kzalloc(strlen_user((
						(struct job_metadata *)arg)->
						input_file)+1, __GFP_WAIT);
			if (job->job_d->input_file == NULL) {
				error = -ENOMEM;
				goto out_free;
			}
			if (copy_from_user(job->job_d->input_file,
				((struct job_metadata *)arg)->input_file,
				strlen_user(((struct job_metadata *)
						arg)->input_file))) {
				error = -EINVAL;
				kfree(job->job_d->input_file);
				goto out_free;
			}

			job->job_d->output_file = kzalloc(strlen_user((
						(struct job_metadata *)arg)->
						output_file)+1, __GFP_WAIT);
			if (job->job_d->output_file == NULL) {
				error = -ENOMEM;
				kfree(job->job_d->input_file);
				goto out_free;
			}

			if (copy_from_user(job->job_d->output_file,
				((struct job_metadata *)arg)->output_file,
				strlen_user(((struct job_metadata *)
						arg)->input_file))) {
				error = -EINVAL;
				kfree(job->job_d->input_file);
				kfree(job->job_d->output_file);
				goto out_free;
			}
			job->job_d->key = kzalloc(strlen_user((
					(struct job_metadata *)arg)->key)+1,
					__GFP_WAIT);
			if (job->job_d->key == NULL) {
				error = -ENOMEM;
				kfree(job->job_d->input_file);
				kfree(job->job_d->output_file);
				goto out_free;
			}

			if (copy_from_user(job->job_d->key,
	       			((struct job_metadata *)arg)->key,
	                         strlen_user(((struct job_metadata *)
						 arg)->key))) {
				 error = -EINVAL;
				 kfree(job->job_d->input_file);
				 kfree(job->job_d->output_file);
				 kfree(job->job_d->key);
				 goto out_free;
		        }
			break;
		default:
			printk("In default\n");
			break;
	}



	goto out;

out_free:
	kfree(job);

out:
	return error;


}

static int __init init_sys_submitjob(void)
{
	printk("installed new sys_submitjob module\n");
	if (sysptr == NULL) {
		sysptr = submitjob;
		/*
		 * hw3_assignment = create_workqueue("hw3_assignment");
		 */
		INIT_LIST_HEAD(&jobs->job_q);
	}
	return 0;
}


