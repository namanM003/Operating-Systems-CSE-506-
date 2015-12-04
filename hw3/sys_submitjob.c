#include <asm/page.h>
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
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "job_queue.h"
#define MAX 128
#define NETLINK_USER 31

asmlinkage extern long (*sysptr)(void *arg, int argslen);

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

struct sock *nl_sk = NULL;
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
		printk("Sleeping\n");
		wait_event_interruptible(waitqueue_consumer, condition == 0);
	} else {
		mutex_unlock(&lock);
	}

	job = NULL;
	if (!access_ok(VERIFY_READ, arg, sizeof(struct job_metadata))) {
		error = -EACCES;
		goto out;
	}
	job = kzalloc(sizeof(struct job_queue), __GFP_WAIT);
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
		job->job_d.algorithm = kzalloc(
			strlen_user(((struct job_metadata *)arg)->algorithm)+1,
			__GFP_WAIT);
		if (copy_from_user(job->job_d.algorithm,
			((struct job_metadata *)arg)->algorithm,
			strlen_user(((struct job_metadata *)arg)->algorithm))) {
			error = -EINVAL;
			//DO REST OF FREEING
			goto out_free;
		}
		break;
	case 2:
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
		job->job_d.algorithm = kzalloc(
			strlen_user(((struct job_metadata *)arg)->algorithm)+1,
			__GFP_WAIT);
		if (copy_from_user(job->job_d.algorithm,
			((struct job_metadata *)arg)->algorithm,
			strlen_user(((struct job_metadata *)arg)->algorithm))) {
			error = -EINVAL;
			//DO REST OF FREEING
			goto out_free;
		}
		break;
	case 3:
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
		job->job_d.algorithm = kzalloc(
			strlen_user(((struct job_metadata *)arg)->algorithm)+1,
			__GFP_WAIT);
		if (copy_from_user(job->job_d.algorithm,
			((struct job_metadata *)arg)->algorithm,
			strlen_user(((struct job_metadata *)arg)->algorithm))) {
			error = -EINVAL;
			//DO REST OF FREEING
			goto out_free;
		}

		//job->job_d.type = 3;
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
	list_add_tail(&job->job_q, &jobs->job_q);

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


static int kargs_valid(const struct job_metadata data)
{
	int ret = 0;
	int i = 0;
	char *ciphers[] = { "aes", "blowfish", "des" };
	int valid_cipher = 0;
	int cipher_len = sizeof(ciphers) / sizeof(ciphers[0]);

	struct file *ifilp = NULL;
	struct file *ofilp = NULL;

	if (!((data.operation == 1) || (data.operation == 2))) {
		printk("xcrypt: invalid operation\n");
		ret = -EINVAL;
		goto out_valid;
	}

	if (!data.input_file || !*data.input_file) {
		printk("xcrypt: invalid input file path\n");
		ret = -EINVAL;
		goto out_valid;
	}

	if ((data.rename && data.overwrite) || (data.rename && data.delete_f)) {
		printk("xcrypt: invalid options\n");
		ret = -EINVAL;
		goto out_valid;
	}

	if (data.delete_f && data.overwrite) {
		printk("xcrypt: invalid options\n");
		ret = -EINVAL;
		goto out_valid;
	}

	if (!data.output_file || !*data.output_file) {
		printk("xcrypt: invalid output file path\n");
		ret = -EINVAL;
		goto out_valid;
	}

	ifilp = filp_open(data.input_file, O_RDONLY, 0);
	if (!ifilp || IS_ERR(ifilp)) {
		printk("xcrypt: cannot open input file %d\n",
		       (int)PTR_ERR(ifilp));
		ret = -ENOENT;
		goto out_valid;
	}

	if (!ifilp->f_op->read) {
		printk("xcrypt: cannot read input file %d\n",
		       (int)PTR_ERR(ifilp));
		ret = -EIO;
		goto out_valid;
	}

	ofilp = filp_open(data.output_file, O_RDWR | O_TRUNC, 0);
	if (ofilp && !IS_ERR(ofilp)) {
		if (ifilp->f_inode == ofilp->f_inode) {
			printk("xcrypt: outfile is same as the infile\n");
			ret = -EPERM;
			goto out_valid;
		}
		if (!ofilp->f_op->write) {
			printk("xcrypt: cannot write output file %d\n",
			       (int)PTR_ERR(ofilp));
			ret = -EIO;
			goto out_valid;
		}
	}

	for (i = 0; i < cipher_len; ++i) {
		printk("Cipher: %s\n", ciphers[i]);
		if (strcmp(ciphers[i], data.algorithm) == 0) {
			valid_cipher = 1;
		}
	}

	if (valid_cipher != 1) {
		printk("xcrypt: cipher invalid or not supported.\n");
		ret = -EINVAL;
		goto out_valid;
	}

out_valid:
	if (ifilp && !IS_ERR(ifilp))
		filp_close(ifilp, NULL);

	if (ofilp && !IS_ERR(ofilp))
		filp_close(ofilp, NULL);

	return ret;
}
static int kargs_valid_xchecksum(const struct job_metadata data)
{
	int ret = 0;
	int i = 0;
	char *hash_alg_supported[] = {"md5", "sha1"};
	int valid_hash_alg = 0;
	int no_supported_hash_alg = sizeof(hash_alg_supported) / sizeof(hash_alg_supported[0]);
	

	struct file *ifilp = NULL;

	

	//if (!data.input_file || !*data.input_file) { 
	if (!data.input_file) {
		printk("xchecksum: invalid input file path\n");
		ret = -EINVAL;
		goto out_valid;
	}
	printk("**1***\n");

	ifilp = filp_open(data.input_file, O_RDONLY, 0);
	if (!ifilp || IS_ERR(ifilp)) {
		printk("xchecksum: cannot open input file %d\n",
		       (int)PTR_ERR(ifilp));
		ret = -ENOENT;
		goto out_valid;
	}
	if (!ifilp->f_op->read) {
		printk("xchecksum: cannot read input file %d\n",
		       (int)PTR_ERR(ifilp));
		ret = -EIO;
		goto out_valid;
	}

	for (i = 0; i < no_supported_hash_alg; ++i) {
                printk("Hash algorithm supported: %s\n", hash_alg_supported[i]);
                if (strcmp(hash_alg_supported[i], data.algorithm) == 0) {
                        valid_hash_alg = 1;
                }
        }
	
		/*if (strcmp("md5", data.algorithm) == 0) {
			valid_hash_alg = 1;
		}*/

	if (valid_hash_alg != 1) {
		printk("xchecksum: Hash algorithm invalid or not supported.\n");
		ret = -EINVAL;
		goto out_valid;
	}
out_valid:
	if (ifilp && !IS_ERR(ifilp))
		filp_close(ifilp, NULL);
	return ret;
}


static inline
unsigned int ll_crypto_tfm_alg_min_keysize(struct crypto_blkcipher *tfm)
{
	return crypto_blkcipher_tfm(tfm)->__crt_alg->cra_blkcipher.min_keysize;
}

static int xcrypt_encrypt(char *src, char *dst, const unsigned char *key,
			  unsigned int buflen, int keylen, const char *algo)
{
	struct crypto_blkcipher *tfm;
	struct scatterlist sdst;
	struct scatterlist ssrc;
	struct blkcipher_desc desc;
	unsigned int min;
	int rc = 0;
	char alg[CRYPTO_MAX_ALG_NAME + 1];
	strcpy(alg, algo);

	/* passing algorithm in a variable instead of a constant string keeps gcc
	 * 4.3.2 happy */
	tfm = crypto_alloc_blkcipher(alg, 0, 0);
	if (IS_ERR(tfm)) {
		printk("sys_xcrypt: failed to allocate cipher handle for %s\n",
		       alg);
		return -EINVAL;
	}

	min = ll_crypto_tfm_alg_min_keysize(tfm);
	rc = crypto_blkcipher_setkey(tfm, key, min);
	if (rc) {
		printk("sys_xcrypt: failed to set key for %s\n", alg);
		goto out;
	}

	sg_init_table(&ssrc, 1);
	sg_set_buf(&ssrc, (const void *)src, buflen);

	sg_init_table(&sdst, 1);
	sg_set_buf(&sdst, (const void *)dst, buflen);

	desc.tfm   = tfm;
	desc.info  = NULL;
	desc.flags = 0;

	rc = crypto_blkcipher_encrypt(&desc, &sdst, &ssrc, buflen);
	if (rc) {
		printk("sys_xcrypt: failed to encrypt for %s\n", alg);
		goto out;
	}

out:
	crypto_free_blkcipher(tfm);
	return rc;
}

static int xcrypt_decrypt(char *src, char *dst, const unsigned char *key,
			  unsigned int buflen, int keylen, const char *algo)
{
	struct crypto_blkcipher *tfm;
	struct scatterlist ssrc;
	struct scatterlist sdst;
	struct blkcipher_desc desc;
	unsigned int min;
	int rc = 0;
	char alg[CRYPTO_MAX_ALG_NAME + 1];
	strcpy(alg, algo);

	/* passing algorithm in a variable instead of a constant string keeps
	 * gcc 4.3.2 happy */
	tfm = crypto_alloc_blkcipher(alg, 0, 0);
	if (IS_ERR(tfm)) {
		printk("sys_xcrypt: failed to allocate cipher handle for %s\n",
		       alg);
		return -EINVAL;
	}

	min = ll_crypto_tfm_alg_min_keysize(tfm);
	rc = crypto_blkcipher_setkey(tfm, key, min);
	if (rc) {
		printk("sys_xcrypt: failed to set key for %s\n", alg);
		goto out;
	}

	sg_init_table(&ssrc, 1);
	sg_set_buf(&ssrc, (const void *)src, buflen);

	sg_init_table(&sdst, 1);
	sg_set_buf(&sdst, (const void *)dst, buflen);

	desc.tfm   = tfm;
	desc.info  = NULL;
	desc.flags = 0;

	rc = crypto_blkcipher_decrypt(&desc, &sdst, &ssrc, buflen);
	if (rc) {
		printk("sys_xcrypt: failed to decrypt for %s\n", alg);
		goto out;
	}

out:
	crypto_free_blkcipher(tfm);
	return rc;
}

/*
 * Read "count" bytes from "filename" into "buf".
 * "buf" is in kernel space.
 */
static int
xcrypt_read_file(const char *filename, char *buf,
		 unsigned long count, loff_t offset)
{
	struct file *filp;
	mm_segment_t oldfs;
	loff_t pos = offset;
	int bytes;

	filp = filp_open(filename, O_RDONLY, 0);

	if (!filp || IS_ERR(filp)) {
		printk("sys_xcrypt: xcrypt_read_file err %d\n",
		       (int)PTR_ERR(filp));
		return -1;
	}

	if (!filp->f_op->read)
		return -2;  /* file(system) doesn't allow reads */

	/* now read count bytes from offset "offset" */
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* The cast to a user pointer is valid due to the set_fs() */
	bytes = vfs_read(filp, (void __user *)buf, count, &pos);
	set_fs(oldfs);

	/* close the file */
	filp_close(filp, NULL);

	return bytes;
}

/*
 * Write "count" bytes from "buf" to "filename".
 * "buf" is in kernel space.
 */
static int
xcrypt_write_file(const char *filename, void *buf,
		  unsigned long count, loff_t offset)
{
	struct file *filp;
	mm_segment_t oldfs;
	loff_t pos = offset;
	int bytes;
	printk("%s file name", filename);
	filp = filp_open(filename, O_CREAT | O_WRONLY, 0644);

	if (!filp || IS_ERR(filp)) {
		printk("sys_xcrypt: xcrypt_write_file err %d\n",
		       (int)PTR_ERR(filp));
		return -1;
	}

	if (!filp->f_op->write)
		return -2;  /* file(system) doesn't allow writes */

	/* now read count bytes from offset "offset" */
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* The cast to a user pointer is valid due to the set_fs() */
	bytes = vfs_write(filp, (void __user *)buf, count, &pos);
	set_fs(oldfs);

	/* close the file */
	filp_close(filp, NULL);

	return bytes;
}

static int xcrypt(struct job_metadata data)
{
	int ret = 0;
	unsigned long count = PAGE_SIZE;
	int r_bytes = 0;
	int w_bytes = 0;
	char *cipher = NULL;
	char *buf = NULL;
	char *key_buf = NULL;
	loff_t r_offset = 0;
	loff_t w_offset = 0;
	int keylen;
	unsigned char *hashkey = NULL;
	struct scatterlist sg_hash;
	struct crypto_hash *tfm = NULL;
	struct hash_desc desc_hash;
	struct blkcipher_desc desc;
	unsigned char* key = NULL;

	char *temp_file = NULL;
	struct file *inp_filp;
	struct file *ofilp;
	struct file *tmp_file;
	mm_segment_t oldfs;

	/*********************NETLINK PART*************/
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "Success";
	char *unsuc = "Unsuccessful";
	int res;
	/****Netlink variables end***/
	ret = kargs_valid(data);
	if (ret < 0) {
		printk("xcrypt: invalid arguments\n");
		goto out;
	}

	cipher = kmalloc(sizeof(char) * 16, GFP_KERNEL);
	if (!cipher) {
		printk("xcrypt: kmalloc couldn't allocate memory\n");
		ret =  -ENOMEM;
		goto out;
	}

	strcpy(cipher, "ctr(");
	strcat(cipher, data.algorithm);
	strcat(cipher, ")");
	printk(KERN_INFO "xcrypt: using %s cipher\n", cipher);

	buf = kmalloc(count, GFP_KERNEL);
	if (!buf) {
		printk("xcrypt: kmalloc couldn't allocate memory\n");
		ret  = -ENOMEM;
		goto out;
	}

	key_buf = kmalloc(sizeof(char) * keylen, GFP_KERNEL);
	if (!key_buf) {
		printk("xcrypt: kmalloc couldn't allocate memory\n");
		ret =  -ENOMEM;
		goto out;
	}

	key = kmalloc(16,__GFP_WAIT);
	if(key==NULL){
		ret = -ENOMEM;
		goto out;
	}
	/* Code to hash key in kernel */
	hashkey = kmalloc(20, __GFP_WAIT);
	if(hashkey == NULL){
		ret = -ENOMEM;
		goto out;
	}

	tfm = crypto_alloc_hash("sha1",0,CRYPTO_ALG_ASYNC);
	desc_hash.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc_hash);

	sg_init_one(&sg_hash,data.key,strlen(data.key));
	crypto_hash_update(&desc_hash,&sg_hash,strlen(data.key));
	crypto_hash_final(&desc_hash,hashkey);
	crypto_free_hash(tfm);
	memcpy(key,hashkey,16);
	keylen = sizeof(key);

	if ((data.rename == 1) || (data.delete_f == 1)) {
		printk("In Rename\n");
		if (data.operation == 1) {
			ret = xcrypt_encrypt(key, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0)
				goto out;

			w_bytes = xcrypt_write_file(data.output_file, key_buf,
						keylen, w_offset);
			if (w_bytes < 0) {
				printk("xcrypt: error in writing file.\n");
				ret = -EIO;
				goto out;
			}
			w_offset = w_offset + w_bytes;
		} else if (data.operation == 2) {
			r_bytes = xcrypt_read_file(data.input_file, key_buf,
						keylen, r_offset);

			if (r_bytes < 0) {
				printk("xcrypt: error in reading file.\n");
				ret  = -EIO;
				goto out;
			}
			r_offset = r_offset + r_bytes;

			ret = xcrypt_decrypt(key_buf, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0) {
				goto out;
			}

			if (memcmp(key, key_buf, keylen) != 0) {
				printk(KERN_INFO "xcrypt: wrong key!\n");
				ret  = -EACCES;
				goto out;
			}
			printk(KERN_INFO "xcrypt: correct key!\n");
		}

		do {
			memset(buf, 0, count);
			r_bytes = xcrypt_read_file(data.input_file, buf,
						   count, r_offset);

			if (r_bytes < 0) {
				ret  = -EIO;
				printk("xcrypt: error in reading file.\n");
				goto out;
			}

			if (r_bytes == count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.output_file,
							    buf, count,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			if (r_bytes < count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.output_file,
							    buf, r_bytes,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			r_offset = r_offset + r_bytes;
			w_offset = w_offset + w_bytes;
		} while (r_bytes == count);
		/* Deleting File*/
		inp_filp = filp_open(data.input_file, O_RDWR, 0644);

		if (!inp_filp || IS_ERR(inp_filp)) {
			printk("xcrypt: xcrypt delete file err %d\n",
			(int)PTR_ERR(inp_filp));
			return -1;
		}

		if (!inp_filp->f_op->write)
			return -2;  /* file(system) doesn't allow writes */

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		mutex_lock(&inp_filp->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink(inp_filp->f_path.dentry->d_parent->d_inode,
			   inp_filp->f_path.dentry, NULL);
		mutex_unlock(&inp_filp->f_path.dentry->d_parent->d_inode->i_mutex);
		set_fs(oldfs);
		filp_close(inp_filp, NULL);
	} else if (data.overwrite == 1) {
		printk("In Overwrite\n");
		/* create temp file */
		temp_file = kmalloc(strlen(data.input_file)+5, __GFP_WAIT);
		memset(temp_file, 0, strlen(data.input_file)+5);
		strcpy(temp_file, data.input_file);
		strcat(temp_file, ".tmp");
		tmp_file = filp_open(temp_file, O_WRONLY | O_CREAT, S_IWUSR);
		if(IS_ERR(tmp_file)){
			ret = -EFAULT;
			goto out;
		}
		filp_close(tmp_file, NULL);
		/* read/write from input to tmp */
		do {
			memset(buf, 0, count);
			r_bytes = xcrypt_read_file(data.input_file, buf, count,
						   r_offset);

			if (r_bytes < 0) {
				ret  = -EIO;
				printk("xcrypt: error in reading file.\n");
				goto out;
			}

			if (r_bytes == count) {
				w_bytes = xcrypt_write_file(temp_file, buf,
							    count, w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			if (r_bytes < count) {
				w_bytes = xcrypt_write_file(temp_file, buf,
							r_bytes, w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			r_offset = r_offset + r_bytes;
			w_offset = w_offset + w_bytes;
		} while (r_bytes == count);
		/* clear input */
		ofilp = filp_open(data.input_file, O_RDWR | O_TRUNC, 0);
		if(IS_ERR(ofilp)){
			ret = -EFAULT;
			goto out;
		}
		filp_close(ofilp, NULL);
		/* encrypt from tmp to input */
		if (data.operation == 1) {
			ret = xcrypt_encrypt(key, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0)
				goto out;

			w_bytes = xcrypt_write_file(data.input_file, key_buf,
						keylen, w_offset);
			if (w_bytes < 0) {
				printk("xcrypt: error in writing file.\n");
				ret = -EIO;
				goto out;
			}
			w_offset = w_offset + w_bytes;
		} else if (data.operation == 2) {
			r_bytes = xcrypt_read_file(temp_file, key_buf,
						keylen, r_offset);

			if (r_bytes < 0) {
				printk("xcrypt: error in reading file.\n");
				ret  = -EIO;
				goto out;
			}
			r_offset = r_offset + r_bytes;

			ret = xcrypt_decrypt(key_buf, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0) {
				goto out;
			}

			if (memcmp(key, key_buf, keylen) != 0) {
				printk(KERN_INFO "xcrypt: wrong key!\n");
				ret  = -EACCES;
				goto out;
			}
			printk(KERN_INFO "xcrypt: correct key!\n");
		}

		do {
			memset(buf, 0, count);
			r_bytes = xcrypt_read_file(temp_file, buf, count,
						   r_offset);

			if (r_bytes < 0) {
				ret  = -EIO;
				printk("xcrypt: error in reading file.\n");
				goto out;
			}

			if (r_bytes == count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.input_file,
							    buf, count,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			if (r_bytes < count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.input_file,
							    buf, r_bytes,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			r_offset = r_offset + r_bytes;
			w_offset = w_offset + w_bytes;
		} while (r_bytes == count);
		/* delete tmp file */
		inp_filp = filp_open(temp_file, O_RDWR, 0644);

		if (!inp_filp || IS_ERR(inp_filp)) {
			printk("xcrypt: xcrypt delete file err %d\n",
			(int)PTR_ERR(inp_filp));
			return -1;
		}

		if (!inp_filp->f_op->write)
			return -2;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		mutex_lock(&inp_filp->f_path.dentry->d_parent->d_inode->i_mutex);
		vfs_unlink(inp_filp->f_path.dentry->d_parent->d_inode,
			   inp_filp->f_path.dentry, NULL);
		mutex_unlock(&inp_filp->f_path.dentry->d_parent->d_inode->i_mutex);
		set_fs(oldfs);
		filp_close(inp_filp, NULL);
	} else {
		if (data.operation == 1) {
			ret = xcrypt_encrypt(key, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0)
				goto out;

			w_bytes = xcrypt_write_file(data.output_file, key_buf,
						keylen, w_offset);
			if (w_bytes < 0) {
				printk("xcrypt: error in writing file.\n");
				ret = -EIO;
				goto out;
			}
			w_offset = w_offset + w_bytes;
		} else if (data.operation == 2) {
			r_bytes = xcrypt_read_file(data.input_file, key_buf,
						keylen, r_offset);

			if (r_bytes < 0) {
				printk("xcrypt: error in reading file.\n");
				ret  = -EIO;
				goto out;
			}
			r_offset = r_offset + r_bytes;

			ret = xcrypt_decrypt(key_buf, key_buf, key,
					keylen, keylen,
					cipher);
			if (ret < 0) {
				goto out;
			}

			if (memcmp(key, key_buf, keylen) != 0) {
				printk(KERN_INFO "xcrypt: wrong key!\n");
				ret  = -EACCES;
				goto out;
			}
			printk(KERN_INFO "xcrypt: correct key!\n");
		}

		do {
			memset(buf, 0, count);
			r_bytes = xcrypt_read_file(data.input_file, buf, count,
						   r_offset);

			if (r_bytes < 0) {
				ret  = -EIO;
				printk("xcrypt: error in reading file.\n");
				goto out;
			}

			if (r_bytes == count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							count, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.output_file,
							    buf, count,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			if (r_bytes < count) {
				if (data.operation == 1) {
					ret = xcrypt_encrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				} else if (data.operation == 2) {
					ret = xcrypt_decrypt(buf, buf, key,
							r_bytes, keylen,
							cipher);
					if (ret < 0)
						goto out;
				}

				w_bytes = xcrypt_write_file(data.output_file,
							    buf, r_bytes,
							    w_offset);
				if (w_bytes < 0) {
					ret  = -EIO;
					printk("xcrypt: error in writing file.\n");
					goto out;
				}
			}

			r_offset = r_offset + r_bytes;
			w_offset = w_offset + w_bytes;
		} while (r_bytes == count);
	}

out:
	if (buf)
		kfree(buf);

	if (key)
		kfree(key);

	if (hashkey)
		kfree(hashkey);

	if (key_buf)
		kfree(key_buf);

	pid = data.pid;
	switch(ret) {
	case 0:
		printk("Successful\n");
		msg_size = strlen(msg);
		skb_out = nlmsg_new(msg_size, 0);
		nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		strncpy(nlmsg_data(nlh), msg, msg_size);
		res = nlmsg_unicast(nl_sk, skb_out, pid);
		if (res < 0)
		        printk(KERN_INFO "Error while sending bak to user\n");
		break;
	default:
	//	msg = "Unsuccessful\n";
		printk("Unsuccessful\n");
		msg_size = strlen(unsuc);
		skb_out = nlmsg_new(msg_size, 0);
		nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
		strncpy(nlmsg_data(nlh), unsuc, msg_size);

		res = nlmsg_unicast(nl_sk, skb_out, pid);
		if (res < 0)
		        printk(KERN_INFO "Error while sending bak to user\n");
		break;
	}
	return 0;
}

static int xchecksum(struct job_metadata data) {

	int ret = 0;
	unsigned long count = PAGE_SIZE;//page size
	int r_bytes = 0;
	loff_t r_offset = 0;
	char *buf = NULL;
	char *buffer = NULL;
	char *nextchar = NULL;
	struct scatterlist sg;
	struct hash_desc desc;
	char *md5_hash_text = kzalloc(16, __GFP_WAIT);
	/*********************NETLINK PART*************/
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg = "Unsuccessful";
	int res;
	int i = 0; /* Counter to run for loop */

	

	memset(md5_hash_text, 0, 16);

	//Initing the crypto alloc hash
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC); 
	crypto_hash_init(&desc);

	ret = kargs_valid_xchecksum(data);

	if (ret < 0) {
		printk("xchecksum: invalid arguments\n");
		goto out; 
	}

	buf = kmalloc(count, GFP_KERNEL);

	if (!buf) {
		printk("xchecksum: kmalloc couldn't allocate memory\n");
		ret  = -ENOMEM;
		goto out;
	}
	do {
		memset(buf, 0, count);
		r_bytes = xcrypt_read_file(data.input_file, buf, count, r_offset);

		
		if (r_bytes < 0) {
			ret  = -EIO;
			printk("xcrypt: error in reading file.\n");
			goto out;
		}
		///////////////////// My PRINT /////////////

		sg_init_one(&sg, buf, r_bytes);
		crypto_hash_update(&desc, &sg, r_bytes);

		r_offset = r_offset + r_bytes;
		
	} while (r_bytes == count);

	crypto_hash_final(&desc, md5_hash_text); //Compute the final md5 hash after calculating the hash of all parts.
	nextchar = kzalloc(9, __GFP_WAIT);
	buffer = kzalloc(33, __GFP_WAIT);
	for (i=0; i < 16; i++) {
		memset(nextchar, 0, 9);
		snprintf(nextchar, 9, "%02x", md5_hash_text[i]);
		if (strlen(nextchar) > 6) {
			strncat(buffer, &nextchar[6], 2);
			
		} else {
			strncat(buffer, nextchar, strlen(nextchar));
		}
	}


out:
	if (buf)
		kfree(buf);

	pid = data.pid;

	switch(ret) {
	case 0:
		msg_size = 32;
		skb_out = nlmsg_new(msg_size, 0);
		nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		strncpy(nlmsg_data(nlh), buffer, msg_size);
		res = nlmsg_unicast(nl_sk, skb_out, pid);
		kfree(buffer);
		kfree(nextchar);
		break;
	default:
		msg_size = strlen(msg);
		skb_out = nlmsg_new(msg_size, 0);
		nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
		strncpy(nlmsg_data(nlh), msg, msg_size);
		res = nlmsg_unicast(nl_sk, skb_out, pid);
		break;
	}
	crypto_free_hash(desc.tfm);
	return 0;

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
		highest_priority = -1;
		mutex_lock(&lock);
		head = jobs;
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
				//xompress(get_job->job_d);
				break;
			case 3:
				printk("In job type 3\n");
				xchecksum(get_job->job_d);
				break;
			case 4:
				printk("In Job type 4\n");
				break;
			default:
				printk("Nothing to do\n");
			}
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
			wait_event_interruptible(waitqueue_consumer,
						 condition == 1);
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
	struct netlink_kernel_cfg cfg = {
		                .groups = 1,
	};

	printk("installed new sys_submitjob module\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
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
		printk("Consumer thread stopped successfully\n");
	}
	if (nl_sk)
		netlink_kernel_release(nl_sk);
	printk("removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
