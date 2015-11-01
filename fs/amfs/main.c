/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include <linux/module.h>
#include <linux/string.h>

/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int amfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	
	/******************TYPE CAST VOID POINTER BACK TO STRUCT sb_void_data**********************************/
	struct sb_void_data *void_attachment = (struct sb_void_data*)raw_data;
	struct pattern *pat = NULL;
	struct pattern *patterns;
	char *buffer;
//	LIST_HEAD(patterns);
	struct file *pattern_db = NULL;// = filp_open(void_attachment->pattern_db_pointer,O_RDONLY,0);
	int bytes_read = 0;
	int counter = 0;
	char *token = NULL;
	struct inode *inode;
	mm_segment_t old_fs = get_fs();
	printk("Inside read super\n");
	printk("File name %s\n",(char*)void_attachment->pattern_db_pointer);
	pattern_db = filp_open((char*)void_attachment->pattern_db_pointer,O_RDONLY,0);
	printk("Succesfully opened pattern file\n");
	if(pattern_db==NULL || IS_ERR(pattern_db)){
		err = -EINVAL;
		printk("\n Problem with pattern db file\n");
		goto out;
	}
	buffer = kmalloc(PAGE_SIZE,__GFP_WAIT);
	printk("\n Buffer allocated successfully\n");
	//LIST_HEAD(patterns);

	if(buffer==NULL){
		err = -ENOMEM;
		printk("Problem in buffer\n");
		goto close_file;
	}
	memset(buffer,0,PAGE_SIZE);
	set_fs(get_ds());
	if((bytes_read = vfs_read(pattern_db,buffer,PAGE_SIZE,&pattern_db->f_pos)) < 0){
		err = -EFAULT;
		set_fs(old_fs);
		printk("Problem with file reading\n");
		goto freebuf;
	}
	set_fs(old_fs);
	printk("After reading file\n");
	patterns = kmalloc(sizeof(struct pattern),__GFP_WAIT);
	INIT_LIST_HEAD(&patterns->pattern_list);
	printk("Init head done\n");
	while(((token = strsep(&buffer,"\n"))!=NULL) && counter <= bytes_read){
		if(strlen(token)==0){
			counter = counter+1;
			continue;
		}
		pat = (struct pattern*)kmalloc(sizeof(struct pattern),__GFP_WAIT);
		pat->patrn = kmalloc(strlen(token)+1,__GFP_WAIT);
		memset(pat->patrn,0,strlen(token)+1);
		memcpy(pat->patrn,token,strlen(token));
		printk("Pattern %s\n",pat->patrn);
		list_add_tail(&pat->pattern_list,&(patterns->pattern_list));
		counter = counter+strlen(token)+1;
	}
	
	
		
	
/******************************************Pattern fillinf *****************************************************/	
	//char *dev_name = (char *) raw_data;
	//printk("Raw data %s\n",(char*)raw_data);
//	struct inode *inode;

	if (!void_attachment->dev_name) {
		printk(KERN_ERR
		       "amfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(void_attachment->dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"amfs: error accessing "
		       "lower directory '%s'\n", void_attachment->dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) {
		printk(KERN_CRIT "amfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_set_lower_super(sb, lower_sb,void_attachment->pattern_db_pointer,patterns);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       void_attachment->dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);
/*******************CLOSE PATTERN FILE**************************/
freebuf: kfree(buffer);
close_file: filp_close(pattern_db,NULL);
/********************* LABELS DEFINED BY ME*************************/
out:
	return err;
}

struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
//	int fd;
//	char* buf;
//	buf = kmalloc(PAGE_SIZE,__GFP_WAIT);
//	void *lower_path_name = (void *) dev_name;
	printk("%s argument",(char*)(raw_data));
	struct sb_void_data *lower_path_name = kmalloc(sizeof(struct sb_void_data),__GFP_WAIT);
	lower_path_name->dev_name = dev_name;
	lower_path_name->pattern_db_pointer = (char*)raw_data;
//	lower_path_name->patterns = NULL;
	
	//fd = filp_open((char*)raw_data,O_RDONLY,0);
	
	return mount_nodev(fs_type, flags,(void *) lower_path_name,
			   amfs_read_super);
}

static struct file_system_type amfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= AMFS_NAME,
	.mount		= amfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
	int err;

	pr_info("Registering amfs " AMFS_VERSION "\n");

	err = amfs_init_inode_cache();
	if (err)
		goto out;
	err = amfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&amfs_fs_type);
out:
	if (err) {
		amfs_destroy_inode_cache();
		amfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_amfs_fs(void)
{
	amfs_destroy_inode_cache();
	amfs_destroy_dentry_cache();
	unregister_filesystem(&amfs_fs_type);
	pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " AMFS_VERSION
		   " (http://amfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
