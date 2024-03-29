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
#include "amfsctl.h"

static ssize_t amfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	/*****Variable to traverse list and search for pattern in a file ***/
	struct pattern *temp_head = NULL;
	struct pattern *pattern = NULL;
	char *value = kzalloc(5, __GFP_WAIT);
	int flag = 0;
	/************Variable declaration ends*********************/
	if (file->f_inode->i_ino == AMFS_SB(file->f_inode->i_sb)->inode_no) {
		err = -EPERM;
		goto out;
	}
	if (value == NULL) {
		err = -ENOMEM;
		goto out;
	}
	lower_file = amfs_lower_file(file);
	if (amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5) > 0) {
		if (!strncmp(value, AMFS_BADFILE, 3)) {
			err = -EPERM;
			goto freevalue;
		}
	} else if (amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5) !=
			-ENODATA) {
			err = amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5);
			goto freevalue;
	}
	err = vfs_read(lower_file, buf, count, ppos);
	/***code to search for a pattern and return appropriate code ********/
	temp_head = AMFS_SB(file->f_inode->i_sb)->pattern_list_head;
	list_for_each_entry(pattern, &temp_head->pattern_list, pattern_list) {
		if (strstr(buf, pattern->patrn)) {
			flag = 1;
			if (!amfs_setxattr(dentry, AMFS_XATTR_NAME,
						AMFS_BADFILE,
						sizeof(AMFS_BADFILE), 0)) {
				err = -EPERM;
				goto freevalue;
			}
		}
	}
	if (!flag) {
		amfs_setxattr(dentry, AMFS_XATTR_NAME, AMFS_GOODFILE,
				sizeof(AMFS_GOODFILE), 0);
	}
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
freevalue:
	kfree(value);
out:
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	struct pattern *tmp_head = NULL;
	struct pattern *pattern = NULL;
	char *value = NULL;

	if (file->f_inode->i_ino == AMFS_SB(file->f_inode->i_sb)->inode_no) {
		err = -EPERM;
		goto out;
	}
	value = kzalloc(5, __GFP_WAIT);
	if (value == NULL) {
		err = -ENOMEM;
		goto out;
	}
	lower_file = amfs_lower_file(file);
	if (amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5) > 0) {
		if (!strncmp(value, AMFS_BADFILE, 3)) {
			err = -EPERM;
			goto freevalue;
		}
	} else if (amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5) !=
			-ENODATA) {
			err = amfs_getxattr(dentry, AMFS_XATTR_NAME, value, 5);
			goto freevalue;
	}

	/*
	 * Approach: Here I check the buffer which was about to be written if it
	 * is containing bad pattern then I took the approach of neither writing
	 * the content of buffer not setting Extra Attribute for bad file
	 */
	tmp_head = AMFS_SB(file->f_inode->i_sb)->pattern_list_head;
	list_for_each_entry(pattern, &tmp_head->pattern_list, pattern_list) {
		if (strstr(buf, pattern->patrn)) {
			err = -EPERM;
			goto freevalue;
		}
		/* In amfs_write we will not set a file and good if there was no
		 * harmul pattern found during write because we haven't read the
		 * complete file
		 */
	}
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}
freevalue:
	kfree(value);
out:
	return err;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = amfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
	return err;
}

static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	struct pattern *tmp = NULL;
	struct pattern *tmp_head = NULL;
	struct pattern *list_pat; /*Pattern  in the node*/
	int counter = 0;
	char *list_ioctl_buffer = NULL;
	int flag = 0;
	struct list_head *pos = NULL, *q = NULL; /*To delete a node safely*/

	lower_file = amfs_lower_file(file);
	/*************CODE TO SWITCH AS PER IOCTL ROLE**********************/
	switch (cmd) {
	case AMFSCTL_ADD_PATTERN:
				list_pat = NULL;
				tmp_head = AMFS_SB(file->f_inode->i_sb)
					->pattern_list_head;
				if ((char *)arg == NULL || strlen((char *)arg)
								> 63) {
					err = -EINVAL;
					goto out;
				}
				list_for_each_entry(list_pat,
					&tmp_head->pattern_list, pattern_list){
					if (!strcmp(list_pat->patrn,
								(char *)arg)) {
						err = -1;
						goto out;
					}
					counter = counter +1;
				}
				if (counter > 64 || strlen((char *)arg) > 63) {
					err = -EINVAL;
					goto out;
				}
				tmp = (struct pattern *)kzalloc(
					sizeof(struct pattern), __GFP_WAIT);
				tmp->patrn = (char *)kzalloc(strlen((char *)arg)
							+1, __GFP_WAIT);
				strcpy(tmp->patrn, (char *)arg);
				list_add_tail(&tmp->pattern_list,
						&tmp_head->pattern_list);
				err = 0;
				goto out;
	case AMFSCTL_REMOVE_PATTERN:
				tmp_head = AMFS_SB(file->f_inode->i_sb)
							->pattern_list_head;
				list_pat = NULL;
				list_for_each_safe(pos, q,
						&tmp_head->pattern_list){
					list_pat = list_entry(pos,
							struct pattern,
							pattern_list);
					if (!strcmp(list_pat->patrn,
								(char *)arg)) {
						flag = 1;
						err = 0;
						kfree(list_pat->patrn);
						list_del(pos);
						kfree(list_pat);
					}
				}
				goto out;


	case AMFSCTL_READ_PATTERN:
				err = 0;
				tmp_head = AMFS_SB(file->f_inode->i_sb)
					->pattern_list_head;
				list_ioctl_buffer = (char *)kzalloc(PAGE_SIZE,
								__GFP_WAIT);
				list_for_each_entry(tmp,
						&tmp_head->pattern_list,
						pattern_list) {
					strcat(list_ioctl_buffer, tmp->patrn);
					strcat(list_ioctl_buffer, "\n");
				}
				if (copy_to_user((char *)arg,
						list_ioctl_buffer,
						PAGE_SIZE)) {
					err = -EFAULT;
				}
				kfree(list_ioctl_buffer);
				goto out;
	default:
		/* XXX: use vfs_ioctl if/when VFS exports it */
		err = -ENOTTY;
		if (!lower_file || !lower_file->f_op)
			goto out;
		if (lower_file->f_op->unlocked_ioctl)
			err = lower_file->f_op->unlocked_ioctl(lower_file, cmd,
									arg);

		/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS)*/
		if (!err)
			fsstack_copy_attr_all(file_inode(file),
					file_inode(lower_file));
		goto out;
	}
	/*******************IOCTL CODE ENDS HERE *********************/
/*close_pattern_file:
	filp_close(pattern_db_file, NULL);*/
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	lower_file = amfs_lower_file(file);
	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	char *value = NULL;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}
	/******File is valid now check if trying to open pattern db file***/
	if (file->f_inode->i_ino == AMFS_SB(file->f_inode->i_sb)->inode_no) {
		err = -EPERM;
		goto out_err;
	}

	/***************XATTR after checking file exists or not******/
	value = kzalloc(5, __GFP_WAIT);
	if (value == NULL) {
		err = -ENOMEM;
		goto out_err;
	}
	if (amfs_getxattr(file->f_path.dentry, AMFS_XATTR_NAME, value, 5) > 0) {
		if (!strncmp(value, AMFS_BADFILE, 3)) {
			err = -EPERM;
			goto freevalue;
		}
	} else if (amfs_getxattr(file->f_path.dentry, AMFS_XATTR_NAME, value, 5)
		!= -ENODATA) {
		err = amfs_getxattr(file->f_path.dentry, AMFS_XATTR_NAME,
								value, 5);
		goto freevalue;
	}

	/***********************************************************/

	file->private_data =
		kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
freevalue:
	kfree(value);
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};
