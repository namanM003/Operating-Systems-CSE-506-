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
#include <linux/mutex.h>
#include "job_queue.h"
#define MAX 128

asmlinkage extern long (*sysptr)(void *arg, int argslen);
/*
 * struct workqueue_struct *hw3_assigment = NULL;
 */

/* 
 *
 *
 *
 *
 *
 *
 *
 *
 * NOTE# REMEMBER TO CHECK SLEEP AND WAKE UP OF THE SUBMITJOB METHOD 
 *
 *
 *
 *
 *
 *
 *
 *
 *
 * */

struct job_queue *jobs = NULL;
struct job_queue *job = NULL;
int flag = 0; /* This flag is used to kill the thread */
int count = 0;

static DEFINE_MUTEX(lock);

static struct task_struct *consumer = NULL;
static wait_queue_head_t waitqueue_consumer;
int condition = 0;

unsigned int job_id = 1;
asmlinkage long submitjob(void *arg, int argslen)
{	
	int counter = 0;
	int error = 0;
	struct job_queue *head = NULL;
	struct job_queue *next_job  = NULL;
	char *buffer = NULL;
	char *list_job = NULL;
	head = jobs;
	list_for_each_entry(next_job, &jobs->job_q, job_q) {
		counter = counter + 1;
	}
	printk("Value of Counter %d\n,",counter);
	mutex_lock(&lock);
	if (count >= MAX) {
		mutex_unlock(&lock);
		printk("Error: Queue is full\n");
		printk("Sleeping\n"); /* This might not be a good model check once*/
		wait_event_interruptible(waitqueue_consumer, condition == 0);
		
	} else {
		mutex_unlock(&lock);
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
	 * Type 3 Compute Checksum/ Hashing
	 * Type 4: List all available jobs
	 * Type 5: Delete a job
	 * Type 6: Change Priority of a job
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
		job->job_d.algorithm = kzalloc(strlen_user((
					(struct job_metadata *)arg)->algorithm)+1,
					__GFP_WAIT);
		//Didnt checked for memory allocated or not
		if (copy_from_user(job->job_d.algorithm, 
			((struct job_metadata *)arg)->algorithm, 
			strlen_user(((struct job_metadata *)arg)->algorithm))) {
			error = -EINVAL;
			//DO REST OF FREEING
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
		/* Assuming user is sending a buffer equivalent to
			* PAGE_SIZE, if not than allocate buffer reuired and
			* modify program as per the requirement
			*/
		buffer = (char *)kzalloc(PAGE_SIZE, __GFP_WAIT);
		counter = 0;
		list_job = (char *)kzalloc(6, __GFP_WAIT);
		list_for_each_entry(job, &jobs->job_q, job_q) {
			snprintf(list_job, 5, "%u %d",
				job->job_d.jobid, job->job_d.type);
			strncat(buffer, list_job, strlen(list_job));
			strcat(buffer, "\n");
		
		}
		/* using the algorithm field of job metadata to store
			* data about job
			*/
		error = 0;
		if (copy_to_user(((struct job_metadata *)arg)->
			algorithm, buffer, strlen(buffer))) {
			error = -EFAULT;
		}
		kfree(buffer);
		kfree(list_job);
		//error = 0;
		goto out;	
		break;
	case 5:
		/* Code to remove a job from the list */
		error = 0;
		goto out;
		break;
	case 6:
		/* Code to change priority of a job*/
		error = 0;
		goto out;
		break;
	default:
		printk("In default\n");
		error = -EINVAL;
		goto out;
		break;
	}
	mutex_lock(&lock);
	job->job_d.jobid = job_id;
	job_id++;
	list_add_tail(&job->job_q, &(jobs->job_q));
	
	if (!count) {
		printk("Checked condition of counter waking consumer q up\n");

		condition = 1;
		wake_up_interruptible(&waitqueue_consumer);
	}
	/* This count keeps the number of jobs in the queue */
	/* Here only relinquish the lock on the linkedlist */
	count++;
	mutex_unlock(&lock);


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
	int highest_priority = -1;
	struct job_queue *head = NULL;
	struct job_queue *get_job = NULL;
	//struct job_metadata job_data;
	printk("In Kernel Thread\n");
	while (!flag) { /* 
			 *  Should we add condition to
			 * continue till all jobs are over of not?
			 */
		mutex_lock(&lock);
		head = jobs;
		//job_data = NULLi;
		/*
		 * This is so that we can find the highest priority job to be
		 * ran
		 */
		list_for_each_entry(get_job, &head->job_q, job_q) {
			if (get_job->job_d.job_priority > highest_priority) {
				highest_priority = get_job->job_d.job_priority;
			}	
		}
		head = jobs;
		get_job = NULL;

		list_for_each_safe(pos, q, &head->job_q) {
			get_job = list_entry(pos, struct job_queue, job_q);
			/* delting from list so that in MT systems no other thread work
			* on same data 
			*/
			if (get_job->job_d.job_priority != highest_priority) {
				continue;
			}
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
			count--;
			break;

		}
		//mutex_unlock(&lock);
		if (count == 0) {
			condition = 0;
			mutex_unlock(&lock);

			wait_event_interruptible(waitqueue_consumer, condition == 1);
			printk("Thread running again\n");
		} else {
			/* 
			 * Make Condition 0 and call wake_up so that if producer
			 * is sleeping wake it up.
			 */
			condition = 0; /* Should condition use a valu of zero 
					 or should I make one more qait queue*/
			mutex_unlock(&lock);
			wake_up_interruptible(&waitqueue_consumer);
			
		}

	}

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
//		mutex_init(&lock, NULL, NULL);
		
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
