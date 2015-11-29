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
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include "job_queue.h"
#define MAX 128

asmlinkage extern long (*sysptr)(void *arg, int argslen);
/*
 * struct workqueue_struct *hw3_assigment = NULL;
 */

struct job_queue *jobs = NULL;
struct job_queue *job = NULL;
int flag = 0; /* This flag is used to kill the thread */
static struct task_struct *consumer = NULL;
static wait_queue_head_t waitqueue_consumer;
int condition = 0;
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
	printk("Value of Counter %d\n,",&counter);
	if (counter >= MAX) {
		printk("Error: Queue is full\n");
		error = -EAGAIN;
		goto out;
	}
	job = NULL;
	if (!access_ok(VERIFY_READ, arg, sizeof(struct job_metadata))) {
		error = -EACCES;
		goto out;
	}
	job = kzalloc(sizeof(struct job_queue),
		       	__GFP_WAIT);
	if (job == NULL) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(&job->job_d, (struct job_metadata *) arg,
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
			job->job_d.input_file = kzalloc(strlen_user((
						(struct job_metadata *)arg)->
						input_file)+1, __GFP_WAIT);
			if (job->job_d.input_file == NULL) {
				error = -ENOMEM;
				goto out_free;
			}
			if (copy_from_user(job->job_d.input_file,
				((struct job_metadata *)arg)->input_file,
				strlen_user(((struct job_metadata *)
						arg)->input_file))) {
				error = -EINVAL;
				kfree(job->job_d.input_file);
				goto out_free;
			}

			job->job_d.output_file = kzalloc(strlen_user((
						(struct job_metadata *)arg)->
						output_file)+1, __GFP_WAIT);
			if (job->job_d.output_file == NULL) {
				error = -ENOMEM;
				kfree(job->job_d.input_file);
				goto out_free;
			}

			if (copy_from_user(job->job_d.output_file,
				((struct job_metadata *)arg)->output_file,
				strlen_user(((struct job_metadata *)
						arg)->input_file))) {
				error = -EINVAL;
				kfree(job->job_d.input_file);
				kfree(job->job_d.output_file);
				goto out_free;
			}
			job->job_d.key = kzalloc(strlen_user((
					(struct job_metadata *)arg)->key)+1,
					__GFP_WAIT);
			if (job->job_d.key == NULL) {
				error = -ENOMEM;
				kfree(job->job_d.input_file);
				kfree(job->job_d.output_file);
				goto out_free;
			}

			if (copy_from_user(job->job_d.key,
	       			((struct job_metadata *)arg)->key,
	                         strlen_user(((struct job_metadata *)
						 arg)->key))) {
				 error = -EINVAL;
				 kfree(job->job_d.input_file);
				 kfree(job->job_d.output_file);
				 kfree(job->job_d.key);
				 goto out_free;
		        }
			break;
		case 2:
			job->job_d.type = 2;
			break;
		case 3:
			job->job_d.type = 3;
			break;
		case 4:
			job->job_d.type = 4;
			break;
		default:
			printk("In default\n");
			break;
	}
	list_add_tail(&job->job_q, &(jobs->job_q));
	if (!counter) {
		printk("Checked condition of counter waking consumer q up\n");

		condition = 1;
		wake_up_interruptible(&waitqueue_consumer);
	}



	goto out;

out_free:
	kfree(job);

out:
	return error;


}


static int xcrypt(struct job_metadata data) {
	printk("In Encrypt Function\n");
	return 1;
}


static int consume(void *data)
{
	struct list_head *pos = NULL, *q = NULL;
	struct job_queue *head = NULL;
	struct job_queue *get_job = NULL;
	//struct job_metadata job_data;
	printk("In Kernel Thread\n");
run:
	head = jobs;
	//job_data = NULL;
	list_for_each_safe(pos, q, &head->job_q) {
		get_job = list_entry(pos, struct job_queue, job_q);
		/* delting from list so that in MT systems no other thread work
		 * on same data 
		 */
		list_del(pos);
		switch(get_job->job_d.type) {
		case 1:
			printk("In Job Type 1\n");
			//job_data = get_job->job_d;
			xcrypt(get_job->job_d);
			break;
		case 2:
			printk("In Job type 2\n");
			break;
		case 3:
			printk("In job type 3\n");
			break;
		case 4:
			printk("In Job type 4\n");
			break;
		default:
			printk("Nothing to do\n");
		}
		/*
		 * #Note clean the memory as per function inside the specific
		 * functions only
		 */
		/*
		 * Note : cleaning the memory consume by job data structure
		 */
		if (get_job) {
			kfree(get_job);
			get_job = NULL;
		}
		//Write kernel sleep/wait code here.
		//schedule();
		//printk ("Thread going for a sleep\n");
		//add_wait_queue(
		//wake_up_interruptible(&waitqueue_consumer);
		/*
		 * condition = 0;
		wait_event_interruptible(waitqueue_consumer, condition == 1);
		printk("Thread again running\n");
		if (!flag) {
			goto run;
		}
		*/


	}
	
	condition = 0;
	wait_event_interruptible(waitqueue_consumer, condition==1);
	printk("Thread running again\n");
	if (!flag) {
		goto run;
	}

	//goto run;
	return 1;



}

static int __init init_sys_submitjob(void)
{
	printk("installed new sys_submitjob module\n");
	if (sysptr == NULL) {
		sysptr = submitjob;
		/*
		 * hw3_assignment = create_workqueue("hw3_assignment");
		 */
		jobs = kmalloc(sizeof(struct job_queue), __GFP_WAIT);
		INIT_LIST_HEAD(&jobs->job_q);
		consumer = kthread_create(consume, NULL, "consumer");
		init_waitqueue_head(&waitqueue_consumer);
		wake_up_process(consumer);
	}
	return 0;
}

static void  __exit exit_sys_submitjob(void)
{
	flag = 1;
	condition = 1;
	wake_up_interruptible(&waitqueue_consumer);
	if (sysptr != NULL)
		sysptr = NULL;
	if (consumer) {
		kthread_stop(consumer);
		printk("Consumer thread stopped succesfully\n");
	}	
	printk("removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
