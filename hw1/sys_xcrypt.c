#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
asmlinkage extern long (*sysptr)(void *arg);

///////////TYPEDEF for saving user provided inputs////////////
 struct input_data{
	char* input_file;
	char* output_file;
	char* keybuf;
	int keylen;
	int flags;
}((__attribute_packed__));
/////////////TYPEDEF ends here/////////////////////

asmlinkage long xcrypt(void *arg)
{	/******VARIABLE DECLARATIONS**********/
	struct input_data* point = kmalloc(sizeof(struct input_data),__GFP_WAIT);
	if(point==NULL)
		return -EFAULT;
	if(copy_from_user(point,(struct input_data*)arg,sizeof(struct input_data)))
		return -EFAULT;
	point->input_file = kmalloc(strlen_user(((struct input_data*)arg)->input_file)+1,__GFP_WAIT);
	if(copy_from_user(point->input_file,((struct input_data*)arg)->input_file,strlen_user(((struct input_data*)arg)->input_file)+1))
		return -EFAULT;
	point->output_file = kmalloc(strlen_user(((struct input_data*)arg)->output_file)+1,__GFP_WAIT);
	if(copy_from_user(point->output_file,((struct input_data*)arg)->output_file,strlen_user(((struct input_data*)arg)->output_file)+1))
                return -EFAULT;
	point->keybuf = kmalloc(strlen_user(((struct input_data*)arg)->keybuf)+1,__GFP_WAIT);
	if(copy_from_user(point->keybuf,((struct input_data*)arg)->keybuf,strlen_user(((struct input_data*)arg)->keybuf)+1))
		return -EFAULT;


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

	if (arg == NULL)
		return -EINVAL;
	else
		return 0;
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
