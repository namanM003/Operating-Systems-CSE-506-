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

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *amfs_inode_cachep;

/* final actions when unmounting a file system */
static void amfs_put_super(struct super_block *sb)
{
	struct amfs_sb_info *spd;
	struct super_block *s;
	struct pattern *list_pat;
	struct pattern *list_head;
	struct list_head *pos, *q;
	char *pattern_file_name;
	struct file *pattern_file = NULL;
	char delimeter = '\n';
	mm_segment_t old_fs;
	pattern_file_name = kzalloc(strlen(AMFS_SB(sb)->pattern_db)+1,
					__GFP_WAIT);
	strcpy(pattern_file_name, AMFS_SB(sb)->pattern_db);
	spd = AMFS_SB(sb);
	if (!spd)
		return;
	/* Freeing memory allocated for storing patterns and list nodes*/
	list_head = (struct pattern *)AMFS_SB(sb)->pattern_list_head;
	/* Freeing memory allocated to pattern db file name*/
	kfree(AMFS_SB(sb)->pattern_db);
	/* decrement lower super references */
	s = amfs_lower_super(sb);
	amfs_set_lower_super(sb, NULL, NULL, NULL, 0);
	atomic_dec(&s->s_active);
	kfree(spd);
	sb->s_fs_info = NULL;
	/*******Copy Pattern db back to file ******/
	old_fs = get_fs();
	pattern_file = filp_open(pattern_file_name, O_WRONLY | O_TRUNC, 0);
	/* If pattern file is deleted by user then just empty the list 
	 * but dont create a new pattern file and write to it
	 */
	if (IS_ERR(pattern_file) || pattern_file == NULL) {
		list_for_each_safe(pos, q, &list_head->pattern_list){
			list_pat = list_entry(pos, struct pattern,
					pattern_list);
			kfree(list_pat->patrn);
			list_del(pos);
			kfree(list_pat);
		}
		goto out;
	}
	list_for_each_safe(pos, q, &list_head->pattern_list) {
		list_pat = list_entry(pos, struct pattern, pattern_list);
		set_fs(get_ds());
		vfs_write(pattern_file, list_pat->patrn, strlen(list_pat->patrn), &pattern_file->f_pos);
		vfs_write(pattern_file, &delimeter, 1, &pattern_file->f_pos);
		set_fs(old_fs);
		kfree(list_pat->patrn);
		list_del(pos);
		kfree(list_pat);
	}
	filp_close(pattern_file, NULL);
out:
	kfree(pattern_file_name);

}

static int amfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	amfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = AMFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int amfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "amfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void amfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = amfs_lower_inode(inode);
	amfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *amfs_alloc_inode(struct super_block *sb)
{
	struct amfs_inode_info *i;

	i = kmem_cache_alloc(amfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct amfs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void amfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(amfs_inode_cachep, AMFS_I(inode));
}

/* amfs inode cache constructor */
static void init_once(void *obj)
{
	struct amfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int amfs_init_inode_cache(void)
{
	int err = 0;

	amfs_inode_cachep =
		kmem_cache_create("amfs_inode_cache",
				  sizeof(struct amfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!amfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* amfs inode cache destructor */
void amfs_destroy_inode_cache(void)
{
	if (amfs_inode_cachep)
		kmem_cache_destroy(amfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void amfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = amfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

const struct super_operations amfs_sops = {
	.put_super	= amfs_put_super,
	.statfs		= amfs_statfs,
	.remount_fs	= amfs_remount_fs,
	.evict_inode	= amfs_evict_inode,
	.umount_begin	= amfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= amfs_alloc_inode,
	.destroy_inode	= amfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};
