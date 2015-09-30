#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h> //CHECK WHETEHR REQUIRED OR NOT
#include <linux/string.h>
#include <linux/cypto.h>
#include "input_data.h"
//#include <sys/stat.h>
asmlinkage extern long (*sysptr)(void *arg);

///////////TYPEDEF for saving user provided inputs////////////
/* struct input_data{
	char* input_file;
	char* output_file;
	char* keybuf;
	int keylen;
	int flags;
}((__attribute_packed__));*/
/////////////TYPEDEF ends here/////////////////////

asmlinkage long xcrypt(void *arg)
{	/******VARIABLE DECLARATIONS**********/
	struct input_data* point = kmalloc(sizeof(struct input_data),__GFP_WAIT);
	struct file *input_f = (struct file*)NULL;
	struct file *output_f = (struct file *)NULL;
	struct file *tmp_file = (struct file *)NULL;
	char *crypt_algo = "aes";
	char* temp_file;
	long buffersize = PAGE_SIZE;
	char* buf;
	char* buf_crypto;
	int mode = CRYPTO_TFM_MODE_CBC;
	char key[16];
	struct crypto_tfm *tfm;
	char *decrypted;
	mm_segment_t fs;
	int bytes_read = 0;
	int padding = 0;
	//struct stat statbuf;
	int error = 0;
	if(arg==NULL){
		error = -EINVAL;
		goto LERROR;
	}
	if(point==NULL){
		error = -ENOMEM;
		goto LERROR;
	}
	if(!access_ok(VERIFY_READ,arg,sizeof(struct input_data))){
		error = -EACCES;
		goto LERROR;
	}
	if(copy_from_user(point,(struct input_data*)arg,sizeof(struct input_data))){
		error =  -EFAULT;
		goto LERROR;
	}

	/**********CODE TO COPY INPUT FILE PATH/NAME****************/
	////////SEARCH WHICH ERROR CODE TO RETURN FOR NULL INPUT FILE ARGUMENT///////////////////
	if(((struct input_data*)arg)->input_file == NULL){
		printk("input file argument passed not passed\n");
		error = -EINVAL;
		goto LERROR;
	}
	/////////////////////////////////////////////////////////////////////////////////////////
	point->input_file = kmalloc(strlen_user(((struct input_data*)arg)->input_file)+1,__GFP_WAIT);
	if(point->input_file==NULL){
		error = -ENOMEM;
		goto FREEINFILE;
	}
	if(!access_ok(VERIFY_READ,((struct input_data*)arg)->input_file,strlen_user(((struct input_data*)arg)->input_file)+1)){
		error = -EACCES;
		goto FREEINFILE;
	}
	if(copy_from_user(point->input_file,((struct input_data*)arg)->input_file,strlen_user(((struct input_data*)arg)->input_file)+1)){
		error = -EFAULT;
		goto FREEINFILE;
	}


	/***********CODE TO COPY OUTPUT FILE PATH/NAME************/
	///////////SEARCH WHICH ERROR CODE TO RETURN FOR NULL OUTPUT FILE ARGUMENT///////////
	if(((struct input_data*)arg)->output_file==NULL){
		printk("Missing output file argument\n");
		error = -EINVAL;
		goto FREEINFILE;
	}
	////////////////////////////////////////////////////////////////////////////////////
	point->output_file = kmalloc(strlen_user(((struct input_data*)arg)->output_file)+1,__GFP_WAIT);
	if(point->output_file==NULL){
		error = -ENOMEM;
		goto FREEOUTFILE;
	}
	if(!access_ok(VERIFY_READ,((struct input_data*)arg)->output_file,strlen_user(((struct input_data*)arg)->output_file)+1)){
                error = -EACCES;
		goto FREEOUTFILE;
	}
	if(copy_from_user(point->output_file,((struct input_data*)arg)->output_file,strlen_user(((struct input_data*)arg)->output_file)+1)){
		error = -EFAULT;
		goto FREEOUTFILE;
	}
	/********CODE TO COPY KEY PHRASE*******************/
	 if(((struct input_data*)arg)->keybuf==NULL){
                printk("Missing passphrase \n");
                error = -EINVAL;
                goto FREEOUTFILE;
        }

	point->keybuf = kmalloc(strlen_user(((struct input_data*)arg)->keybuf)+1,__GFP_WAIT);
	if(point->keybuf==NULL){
		error =  -ENOMEM;
		goto FREEKEYBUF;
	}
	if(!access_ok(VERIFY_READ,((struct input_data*)arg)->keybuf,strlen_user(((struct input_data*)arg)->keybuf)+1)){
		error = -EACCES;
		goto FREEKEYBUF;
	}
	if(copy_from_user(point->keybuf,((struct input_data*)arg)->keybuf,strlen_user(((struct input_data*)arg)->keybuf)+1)){
		error = -EFAULT;
		goto FREEKEYBUF;
	}
	/*****************END OF COPYING********************/
	/****************FILE VALIDATIONS CODE START HERE***********************/
	

	//point->input_file = arg->input_file;
	//char* input_file = (char*)ptr[1];
/*	char* output_file = (char*)(ptr[2]);
	char* keybuf = (char*)(ptr[3]);
	char* keylen = (char*)(ptr[4]);
	char* flags = (char*)(ptr[5]);*/

	/*******VARIABLE DECLARATIONS END HERE*******/
	//struct file *input_f,*output_f;
	input_f = filp_open(point->input_file,O_RDONLY,0);
	if(IS_ERR(input_f)){
		error = -EFAULT;
		goto FREEKEYBUF;
	}
	printk("\n In kernel tryint to crete\n\n");
	output_f = filp_open(point->output_file,O_WRONLY,0);
	printk("If I dont get printed above line is a problem\n");
	if(IS_ERR(output_f) || output_f == NULL){
		//output_f = filp_open(point->output_file,O_WRONLY | O_CREAT,input_f->f_inode->i_mode | S_IWUSR);
		if(output_f==NULL){
			printk("File doesnt exist\n");
		}
		else{
			printk("You dont have permission to read");
			error = -EACCES;
			goto CLOSEINPUTFILE;
		}
		/*printk("\n\n\nCreating a file from inside a kernel\n\n\n");
		// output_f = filp_open(point->output_file,O_WRONLY | O_CREAT,0777);   //THIS IS TEST CODE
		if(IS_ERR(output_f)){
			printk("ERROR: Unable create a new file\n");
			error = -EFAULT;
			goto CLOSEINPUTFILE;
		}*/
	}
	else{
		if(!(output_f->f_inode->i_mode & FMODE_WRITE)){
			error = -EACCES;
			flip_close(output_f,NULL);
			goto CLOSEINPUTFILE;
		}
		flip_close(output_f,NULL);
		//CHECK DO WE NEED TO DO THIS ANYWAY WE WILL BE RENAMING TMP FILE TO OUTPUTFILE NAME.
		//filp_close(output_f,NULL);
		//output_f = filp_open(point->output_file,O_WRONLY,0);
	}
		
	/*if(IS_ERR(output_f)){
		if(errno==ENOENT){
			output_f = filp_open(point->output_file,O_WRONLY | O_CREAT,input_f->f_inode->i_mode);
		}
		if(errno==EACCES){
			printk("User dont have permission to write to file");
			goto CLOSEINPUTFILE;
		}
	}*/
	
	if(input_f->f_inode->i_ino == output_f->f_inode->i_ino){
		if(input_f->f_inode->i_sb->s_type->name == output_f->f_inode->i_sb->s_type->name){
			error = -EINVAL;
			printk("Input and Output file are same. Exiting\n");
			goto CLOSEOUTPUTFILE;
		}
	}
	/******CODE TO CREATE TEMP FILE AND WRITE ENCRYPTED DATA TO IT*************************/
	temp_file = kmalloc(strlen(point->output_file)+5,__GFP_WAIT);
	memset(temp_file,0,strlen(point->output_file)+5);
	strcpy(temp_file,point->output_file/*,strlen(point->output_file)*/);
	strcat(temp_file,".tmp");
	tmp_file = filp_open(temp_file,O_WRONLY | O_CREAT,input_f->f_inode->i_mode | S_IWUSR);
	if(IS_ERR(tmp_file)){
		error = -EFAULT;
		goto CLOSEOUTPUTFILE;
	}
	buf = kmalloc(PAGE_SIZE,__GFP_WAIT);
	
	if(buf==NULL){
		error = -ENOMEM;
		goto CLOSEOUTPUTFILE;
	}
	buf_crypto = kmalloc(PAGE_SIZE,__GFP_WAIT);
	if(buf_crypto==NULL){
		error = -ENOMEM;
		goto FREEBUF;
	}
	fs = get_fs();
	//set_fs(get_ds());
	//input_f->f_op->read(input_f,buf,buffersize,&input_f->f_pos);
	////// CRYPTO//////
	
	memset(key, 0, sizeof(key));
	tfm = crypto_alloc_cipher(algo,4,CRYPTO_ALG_ASYNC);
	crypto_cipher_setkey(tfm,point->keybuf,16);
	do{
		printk("In Loop\n");
		set_fs(get_ds());
		memset(buf,0,buffersize)
		bytes_read = vfs_read(input_f,buf,buffersize,&input_f->f_pos);
		if(bytes_read<0){
			error = -EFAULT;
			set_fs(fs);
			goto FREEOUTPUTBUF;
		}
		set_fs(fs);
	
		////////////////////////// CRYPTO CODE //////////////////////////////////////////////////////////////
		 
		
		if(bytes_read==0)
			break;
		set_fs(get_ds());	
		if(bytes_read==PAGE_SIZE){
			crypto_cipher_encrypt_one(tfm,buf_crypto,buf);
			vfs_write(tmp_file,buf_crypto,buffersize,&tmp_file->f_pos);    ///\CHANGE SRC BUFFER TO WHERE YOU WILL WRITE ENCRYPTED DATA
		}
		else{
			padding = bytes_read%16;
			crypto_cipher_encrypt_one(tfm,buf_crypto,bytes_read+padding);
			vfs_write(tmp_file,buf,bytes_read+1,&tmp_file->f_pos);
			printk("Printing buf %s\n",buf);
		}
		set_fs(fs);
	}while(bytes_read>0);
		
	filp_close(tmp_file,NULL);

	////////LINKING UNLINK CODE////////////////////////////////////////////////

	





	//flip_close(point->output_file);
	//unlink(point->output);
	//link(tmp_file,point->output_file);
	//unlink(tmp_file);
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	printk("New tmp file name is %s\n",temp_file);
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	printk("xcrypt received arg %p\n", arg);
	//printk("Size of pointer buffer %d\n",sizeof(ptr));
	/***********ARGUMENTS VALIDATION CODE****************************/
	printk("\nTrying to print in kernel\n");
	//char* ptr = (char*)arg;
	printk("Infile %s\n",point->input_file);
	printk("Out_file %s\n",point->output_file);
	printk("Key %s\n",point->keybuf);
	printk("Keylength %d\n",point->keylen);
	printk("Flags %d\n",point->flags);
	//printk("Argumnets Received %s",ptr);

	/**********ARGUMNETS VALIDATION END*************************/
	/***********LABELS TO FREE AND CLEAN MEMORY**********/
	FREEOUTPUTBUF: kfree(buf_crypto);
	FREEBUF: kfree(buf);
	//CLOSEOUTPUTFILE: filp_close(output_f,NULL);
	CLOSEINPUTFILE: filp_close(input_f,NULL);
	FREEKEYBUF: kfree(point->keybuf);
	FREEOUTFILE: kfree(point->output_file);
	FREEINFILE: kfree(point->input_file);
	LERROR: kfree(point);
		return error;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
