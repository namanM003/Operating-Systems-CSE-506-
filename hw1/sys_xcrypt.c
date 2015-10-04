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
#include "input_data.h"
asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long xcrypt(void *arg)
{	/******VARIABLE DECLARATIONS**********/
	struct kstat stat,stat_input;
	struct input_data* point = kmalloc(sizeof(struct input_data),__GFP_WAIT);
	struct file *input_f = (struct file*)NULL;
	struct file *output_f = (struct file *)NULL;
	struct file *tmp_file = (struct file *)NULL;
	/////VARIABLE FOR HASHING IN KERNE/////////
	/////CODE EXAMPLE TAKEN FROM http://stackoverflow.com/questions/16861332/how-to-compute-sha1-of-an-array-in-linux-kernel ///////////////////////////////
	struct scatterlist sg_hash;
	struct crypto_hash *tfm = NULL;
	struct hash_desc desc_hash;
	unsigned char *hashkey;
	unsigned char* keyFromFile;
	char* temp_file;
	char* buf;
	char* buf_crypto;
	char *cipher = "ctr(aes)";
	unsigned char* key;
	struct crypto_blkcipher *blkcipher = NULL;
	struct blkcipher_desc desc;
	int file_exist = 0;
	mm_segment_t fs;
	int bytes_read = 0;
	struct scatterlist sg_in,sg_out;
	int error = 0;
	
	/*******VARIABLE DECLARATIONS END HERE*******/
	/*******************VALIDATIONS START HERE************************/
	if(arg==NULL){
		error = -EINVAL;
		goto LERROR;
	}
	if(point==NULL){
		error = -ENOMEM;
		goto LERROR;
	}
	point->flags = -1;
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

	point->keybuf = kmalloc(16,__GFP_WAIT);
	if(point->keybuf==NULL){
		error =  -ENOMEM;
		goto FREEKEYBUF;
	}
	if(!access_ok(VERIFY_READ,((struct input_data*)arg)->keybuf,strlen_user(((struct input_data*)arg)->keybuf)+1)){
		error = -EACCES;
		goto FREEKEYBUF;
	}
	if(copy_from_user(point->keybuf,((struct input_data*)arg)->keybuf,strlen_user(((struct input_data*)arg)->keybuf))){
		error = -EFAULT;
		goto FREEKEYBUF;
	}
	/*****************END OF COPYING********************/
	/****************FILE VALIDATIONS CODE START HERE***********************/
	
	/////////////////////////////INPUT FILE VALIDATION CODE STARTS HERE///////////////////////////////////
	input_f = filp_open(point->input_file,O_RDONLY,0);
	if(IS_ERR(input_f) || input_f==NULL){
		printk("Input file doesn't exist\n");
		error = -EFAULT;
		goto FREEKEYBUF;
	}
	if(!S_ISREG(input_f->f_inode->i_mode)){
		error = -EBADF;
		goto CLOSEINPUTFILE;
	}
	fs = get_fs();
	set_fs(get_ds());
	if(vfs_stat(point->input_file,&stat_input)){
		set_fs(fs);
		error = -EINVAL;
		goto CLOSEINPUTFILE;
	}
	set_fs(fs);
	if(!(stat_input.mode & S_IRUSR)){
		error = -EACCES;
		goto CLOSEINPUTFILE;
	}
//	printk("\n In kernel trying to crete\n\n");
	/////////////////////////INPUT FILE VALIDATION CODE ENDS/////////////////////////////////////////////
	/////////////////////////OUTPUT FILE VALIDATION CODE STARTS HERE/////////////////////////////////////
	output_f = filp_open(point->output_file,O_RDONLY,0);
	if(IS_ERR(output_f) || output_f == NULL){
		if(output_f==NULL){
			printk("File doesnt exist\n");
		}
	}
	else{
		file_exist = 1;
		if(!S_ISREG(output_f->f_inode->i_mode)){
         	        error = -EBADF;
                	goto CLOSEINPUTFILE;
        	}
		fs = get_fs();
		set_fs(get_ds());
		if(vfs_stat(point->output_file,&stat)){
			set_fs(fs);
			error = -EINVAL;
			goto CLOSEINPUTFILE;
		}
		set_fs(fs);
		if(!(stat.mode & S_IWUSR)){
			error = -EACCES;
			filp_close(output_f,NULL);
			goto CLOSEINPUTFILE;
		}
		if(input_f->f_inode->i_ino == output_f->f_inode->i_ino){
	                if(input_f->f_inode->i_sb->s_type->name == output_f->f_inode->i_sb->s_type->name){
        	                error = -EINVAL;
                	        printk("Input and Output file are same. Exiting\n");
				filp_close(output_f,NULL);
                        	goto CLOSEINPUTFILE;
                	}
        	}	

	}
	/////////////////OUTPUT FILE VALIDATION CODE ENDS HERE//////////////////////////////////

	/******CODE TO CREATE TEMP FILE AND WRITE ENCRYPTED DATA TO IT*************************/
	temp_file = kmalloc(strlen(point->output_file)+5,__GFP_WAIT);
	memset(temp_file,0,strlen(point->output_file)+5);
	strcpy(temp_file,point->output_file/*,strlen(point->output_file)*/);
	strcat(temp_file,".tmp");
	tmp_file = filp_open(temp_file,O_WRONLY | O_CREAT,stat_input.mode | S_IWUSR);
	if(IS_ERR(tmp_file)){
		error = -EFAULT;
		goto CLOSEINPUTFILE;
	}
	buf = kmalloc(PAGE_SIZE,__GFP_WAIT);
	
	if(buf==NULL){
		error = -ENOMEM;
		goto CLOSEINPUTFILE;
	}
	///////////////////////////////// CRYPTO CODE STARTS HERE//////////////////////////////////
	blkcipher = crypto_alloc_blkcipher(cipher,0,CRYPTO_ALG_ASYNC);
	if(IS_ERR(blkcipher)){
		printk("Could not allocate blkcipher handle for %s\n",cipher);
		goto FREEBUF;
	}
	key = kmalloc(16,__GFP_WAIT);
	if(key==NULL){
		error = -ENOMEM;
		goto FREEKEY;
	}
	
	memset(key, 0, 16);
	/////////////////////////////CODE TO HASH KEY IN KERNEL//////////////////////////////////////////////////
	hashkey = kmalloc(20,__GFP_WAIT);
	tfm = crypto_alloc_hash("sha1",0,CRYPTO_ALG_ASYNC);
	desc_hash.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc_hash);
	sg_init_one(&sg_hash,point->keybuf,strlen(point->keybuf));
	crypto_hash_update(&desc_hash,&sg_hash,strlen(point->keybuf));
	crypto_hash_final(&desc_hash,hashkey);
	crypto_free_hash(tfm);
	////////////////////////////////////////////////////////////////////////////////////////////////////////	
	memcpy(key,hashkey,16);
	//printk("HashKey %s\n",hashkey);
	//printk("KeyBuffer %s\n",point->keybuf);
	if(crypto_blkcipher_setkey(blkcipher,key,16)){
		printk("Key could not be set");
		error = -EAGAIN;
		goto FREEKEY;
	}
	//printk("Key value %s\n",key);
	desc.flags = 0;
	desc.tfm = blkcipher;
	buf_crypto = kmalloc(PAGE_SIZE,__GFP_WAIT);
        if(buf_crypto==NULL){
                error = -ENOMEM;
                goto FREEBUF;
        }
        fs = get_fs();
	//////////////////THIS PIECE OF CODE CHECK WHETHER THE FLAG WAS SET OR NOT/////////////////////////
	if(point->flags==-1){
		error = -EINVAL;
		goto FREEOUTPUTBUF;
	}
	////////////////////FLAG CHECK CODE ENDS HERE/////////////////////////////////////////////////////

	if(point->flags==1){
		set_fs(get_ds());
		vfs_write(tmp_file,key,16,&tmp_file->f_pos);
		set_fs(fs);
		do{
			printk("In Loop\n");
			set_fs(get_ds());
			memset(buf,0,PAGE_SIZE);
			memset(buf_crypto,0,PAGE_SIZE);
			bytes_read = vfs_read(input_f,buf,PAGE_SIZE,&input_f->f_pos);
			printk("Bytes Read %d\n",bytes_read);
			if(bytes_read<0){
				error = -EFAULT;
				set_fs(fs);
				goto FREEOUTPUTBUF;
			}
			set_fs(fs);
			printk("\nData in Buffer%s\n",buf);
			////////////////////////// CRYPTO CODE //////////////////////////////////////////////////////////////
			 
		
			if(bytes_read==0)
				break;
			set_fs(get_ds());	
			if(bytes_read==PAGE_SIZE){
				sg_init_one(&sg_in,buf,PAGE_SIZE);
				sg_init_one(&sg_out,buf_crypto,PAGE_SIZE);
				crypto_blkcipher_encrypt(&desc,&sg_out,&sg_in, PAGE_SIZE);
				vfs_write(tmp_file,buf_crypto,PAGE_SIZE,&tmp_file->f_pos);   
			}
			else{
				sg_init_one(&sg_in,buf,bytes_read);
				sg_init_one(&sg_out,buf_crypto,bytes_read);
				crypto_blkcipher_encrypt(&desc,&sg_out,&sg_in, bytes_read);
				vfs_write(tmp_file,buf_crypto,bytes_read,&tmp_file->f_pos);
			}
			set_fs(fs);
		}while(bytes_read==PAGE_SIZE);
	}

	if(point->flags==0){
		set_fs(get_ds());
		vfs_read(input_f,buf,16,&input_f->f_pos);
		keyFromFile = kmalloc(16,__GFP_WAIT);
		if(keyFromFile==NULL){
			error = -ENOMEM;
			goto FREEOUTPUTBUF;
		}	
                memcpy(keyFromFile, buf,16);
		if(memcmp(keyFromFile,key,16)){
			error = -EPERM;
			kfree(keyFromFile);
			goto FREEOUTPUTBUF;
		}
		kfree(keyFromFile);
                set_fs(fs);	
		do{
			 printk("In Loop\n");
                        set_fs(get_ds());
                        memset(buf,0,PAGE_SIZE);
                        memset(buf_crypto,0,PAGE_SIZE);
                        bytes_read = vfs_read(input_f,buf,PAGE_SIZE,&input_f->f_pos);
                        printk("Bytes Read %d\n",bytes_read);
                        if(bytes_read<0){
                                error = -EFAULT;
                                set_fs(fs);
                                goto FREEOUTPUTBUF;
                        }
                        set_fs(fs);
                        printk("\nData in Buffer%s\n",buf);
                        ////////////////////////// CRYPTO CODE //////////////////////////////////////////////////////////////


                        if(bytes_read==0)
                                break;
                        set_fs(get_ds());
                        if(bytes_read==PAGE_SIZE){
                                sg_init_one(&sg_in,buf,PAGE_SIZE);
                                sg_init_one(&sg_out,buf_crypto,PAGE_SIZE);
                                crypto_blkcipher_decrypt(&desc,&sg_out,&sg_in, PAGE_SIZE);
                                vfs_write(tmp_file,buf_crypto,PAGE_SIZE,&tmp_file->f_pos); 
                        }
                        else{
                                sg_init_one(&sg_in,buf,bytes_read);
                                sg_init_one(&sg_out,buf_crypto,bytes_read);
                                crypto_blkcipher_decrypt(&desc,&sg_out,&sg_in, bytes_read);
                                vfs_write(tmp_file,buf_crypto,bytes_read,&tmp_file->f_pos);
                        }
                        set_fs(fs);

			
		}while(bytes_read==PAGE_SIZE);
	}
		

	///////////////////////////////////////////////////LINKING UNLINK CODE////////////////////////////////////////////////
	if(file_exist == 1){
		output_f = filp_open(point->output_file,O_RDONLY,0);
		lock_rename(tmp_file->f_path.dentry->d_parent,output_f->f_path.dentry->d_parent);
		vfs_rename(tmp_file->f_path.dentry->d_parent->d_inode, tmp_file->f_path.dentry, output_f->f_path.dentry->d_parent->d_inode, output_f->f_path.dentry, NULL ,0);
		unlock_rename(tmp_file->f_path.dentry->d_parent,output_f->f_path.dentry->d_parent);
	}
	else{
		output_f = filp_open(point->output_file,O_WRONLY | O_CREAT, stat_input.mode | S_IWUSR);
		lock_rename(tmp_file->f_path.dentry->d_parent,output_f->f_path.dentry->d_parent);
                vfs_rename(tmp_file->f_path.dentry->d_parent->d_inode, tmp_file->f_path.dentry, output_f->f_path.dentry->d_parent->d_inode, output_f->f_path.dentry, NULL ,0);
                unlock_rename(tmp_file->f_path.dentry->d_parent,output_f->f_path.dentry->d_parent);
	}





	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	filp_close(tmp_file,NULL);

	/**********ARGUMNETS VALIDATION END*************************/
	/***********LABELS TO FREE AND CLEAN MEMORY**********/
			crypto_free_blkcipher(blkcipher);
			
	FREEOUTPUTBUF: kfree(buf_crypto);
	FREEKEY: kfree(key);
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
