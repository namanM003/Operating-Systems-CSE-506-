#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "input_data.h"
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
