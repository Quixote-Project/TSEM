// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file manages the data structures used to define a security event.
 */

#include <linux/iversion.h>
#include <linux/user_namespace.h>
#include <linux/base64.h>

#include "tsem.h"
#include "../integrity/integrity.h"

static struct kmem_cache *event_cachep;

static void refill_event_magazine(struct work_struct *work)
{
	unsigned int index;
	struct tsem_event *ep;
	struct tsem_work *ws;

	ws = container_of(work, struct tsem_work, work);

	ep = kmem_cache_zalloc(event_cachep, GFP_KERNEL);
	if (!ep) {
		pr_warn("tsem: Cannot refill event magazine.\n");
		return;
	}

	spin_lock(&ws->u.ctx->magazine_lock);
	ws->u.ctx->magazine[ws->index] = ep;
	clear_bit(ws->index, ws->u.ctx->magazine_index);

	/*
	 * The following memory barrier is used to cause the magazine
	 * index to be visible after the refill of the cache slot.
	 */
	smp_mb__after_atomic();
	spin_unlock(&ws->u.ctx->magazine_lock);

	if (index >= ws->u.ctx->magazine_size) {
		kmem_cache_free(event_cachep, ep);
		WARN_ONCE(true, "Refilling event magazine with no slots.\n");
	}
}

static void get_COE(struct tsem_COE *COE)

{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	COE->uid = from_kuid(ns, current_uid());
	COE->euid = from_kuid(ns, current_euid());
	COE->suid = from_kuid(ns, current_suid());

	COE->gid = from_kgid(ns, current_gid());
	COE->egid = from_kgid(ns, current_egid());
	COE->sgid = from_kgid(ns, current_sgid());

	COE->fsuid = from_kuid(ns, current_fsuid());
	COE->fsgid = from_kgid(ns, current_fsgid());

	COE->capeff.mask = current_cred()->cap_effective;
}

static int get_root(struct dentry *dentry, struct tsem_path *path)
{
	int retn = 0;
	struct super_block *sb = dentry->d_sb;
	struct inode *inode = d_backing_inode(sb->s_root);

	if (MAJOR(sb->s_dev) || inode->i_op->rename)
		path->dev = sb->s_dev;
	else {
		path->fstype = kstrdup(sb->s_type->name, GFP_KERNEL);
		if (IS_ERR(path->fstype))
			retn = PTR_ERR(path->fstype);
	}

	return retn;
}

static char *get_path(const struct path *path)
{
	int retn = 0;
	const char *pathname = NULL;
	char *retpath, *pathbuffer = NULL;

	pathbuffer = __getname();
	if (pathbuffer) {
		pathname = d_absolute_path(path, pathbuffer, PATH_MAX);
		if (IS_ERR(pathname)) {
			__putname(pathbuffer);
			pathbuffer = NULL;
			pathname = NULL;
		}
	}

	if (pathname)
		retpath = kstrdup(pathname, GFP_KERNEL);
	else
		retpath = kstrdup(path->dentry->d_name.name, GFP_KERNEL);
	if (!retpath)
		retn = -ENOMEM;

	if (pathbuffer)
		__putname(pathbuffer);
	if (retn)
		retpath = ERR_PTR(retn);
	return retpath;
}

static char *get_path_dentry(const struct dentry *dentry)
{
	int retn = 0;
	const char *pathname = NULL;
	char *retpath, *pathbuffer = NULL;

	pathbuffer = __getname();
	if (pathbuffer) {
		pathname = dentry_path_raw(dentry, pathbuffer, PATH_MAX);
		if (IS_ERR(pathname)) {
			__putname(pathbuffer);
			pathbuffer = NULL;
			pathname = NULL;
		}
	}

	if (pathname)
		retpath = kstrdup(pathname, GFP_KERNEL);
	else
		retpath = kstrdup(dentry->d_name.name, GFP_KERNEL);
	if (!retpath)
		retn = -ENOMEM;

	if (pathbuffer)
		__putname(pathbuffer);
	if (retn)
		retpath = ERR_PTR(retn);
	return retpath;
}

static int fill_path(const struct path *in, struct tsem_path *path)
{
	int retn;

	retn = get_root(in->dentry, path);
	if (retn)
		goto done;

	path->pathname = get_path(in);
	if (IS_ERR(path->pathname)) {
		kfree(path->fstype);
		retn = PTR_ERR(path->pathname);
	}

 done:
	return retn;
}

static int fill_path_dentry(struct dentry *dentry, struct tsem_path *path)
{
	int retn;

	retn = get_root(dentry, path);
	if (retn)
		goto done;

	path->pathname = get_path_dentry(dentry);
	if (IS_ERR(path->pathname)) {
		kfree(path->fstype);
		retn = PTR_ERR(path->pathname);
	}

 done:
	return retn;
}

static int add_file_name(struct tsem_event *ep)
{
	int retn;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	ep->file.name_length = strlen(ep->pathname);
	retn = crypto_shash_finup(shash, ep->pathname, ep->file.name_length,
				  ep->file.name);

 done:
	return retn;
}

static struct tsem_inode_digest *find_digest(struct tsem_inode *tsip)
{
	struct tsem_inode_digest *digest;

	list_for_each_entry(digest, &tsip->digest_list, list) {
		if (!strcmp(digest->name, tsem_context(current)->digestname))
			return digest;
	}

	return NULL;
}

static struct tsem_inode_digest *add_digest(struct tsem_context *ctx,
					    struct tsem_inode *tsip)
{
	struct tsem_inode_digest *digest;

	digest = kzalloc(sizeof(*digest), GFP_KERNEL);
	if (!digest)
		return NULL;

	digest->name = kstrdup(tsem_context(current)->digestname, GFP_KERNEL);
	if (!digest->name)
		return NULL;

	list_add(&digest->list, &tsip->digest_list);

	return digest;
}

static struct file *open_event_file(struct file *file, unsigned int *status)
{
	int flags;
	struct file *alt_file;

	if (!(file->f_mode & FMODE_CAN_READ)) {
		file->f_mode |= FMODE_CAN_READ;
		*status |= 4;
	}
	if (file->f_mode & FMODE_READ)
		return file;

	flags = file->f_flags & ~(O_WRONLY | O_APPEND | O_TRUNC | O_CREAT |
				  O_NOCTTY | O_EXCL);
	flags |= O_RDONLY;

	alt_file = dentry_open(&file->f_path, flags, file->f_cred);
	if (!IS_ERR(alt_file)) {
		*status |= 1;
		return alt_file;
	}

	file->f_flags |= FMODE_READ;
	*status |= 2;
	return file;
}

static int get_file_digest(struct file *file, struct inode *inode,
			   loff_t size, u8 *digest)
{
	u8 *bufr;
	int retn = 0, rsize;
	unsigned int open_status = 0;
	loff_t posn = 0;
	struct file *read_file;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	bufr = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bufr) {
		retn = -ENOMEM;
		goto done;
	}

	if (!likely(file->f_op->read || file->f_op->read_iter)) {
		retn = -EINVAL;
		goto done;
	}
	read_file = open_event_file(file, &open_status);

	while (posn < size) {
		rsize = integrity_kernel_read(read_file, posn, bufr, 4096);
		if (rsize < 0) {
			retn = rsize;
			break;
		}
		if (rsize == 0)
			break;

		posn += rsize;
		retn = crypto_shash_update(shash, bufr, rsize);
		if (retn)
			break;
	}

	kfree(bufr);
	if (!retn)
		retn = crypto_shash_final(shash, digest);

 done:
	if (open_status & 1)
		fput(read_file);
	if (open_status & 2)
		file->f_flags &= ~FMODE_READ;
	if (open_status & 4)
		file->f_flags &= ~FMODE_CAN_READ;
	return retn;
}

static int add_file_digest(struct file *file, struct tsem_file *tfp)
{
	int retn = 0;
	u8 measurement[HASH_MAX_DIGESTSIZE];
	loff_t size;
	struct inode *inode;
	struct tsem_inode *tsip;
	struct tsem_inode_digest *digest;
	struct tsem_context *ctx = tsem_context(current);

	inode = file_inode(file);
	tsip = tsem_inode(inode);

	mutex_lock(&tsip->mutex);
	if (!ctx->external) {
		retn = tsem_model_has_pseudonym(tsip, tfp);
		if (retn < 0)
			goto done;
		if (retn) {
			memcpy(tfp->digest, ctx->zero_digest,
			       tsem_digestsize());
			retn = 0;
			goto done;
		}
	}

	size = i_size_read(inode);
	if (!size) {
		memcpy(tfp->digest, ctx->zero_digest, tsem_digestsize());
		goto done;
	}

	digest = find_digest(tsip);

	if (digest && inode_eq_iversion(inode, digest->version) &&
	    tsip->status == TSEM_INODE_COLLECTED) {
		memcpy(tfp->digest, digest->value, tsem_digestsize());
		goto done;
	}

	tsip->status = TSEM_INODE_COLLECTING;
	retn = get_file_digest(file, inode, size, measurement);
	if (retn) {
		tsip->status = 0;
		goto done;
	}

	if (!digest) {
		digest = add_digest(ctx, tsip);
		if (!digest) {
			retn = -ENOMEM;
			goto done;
		}
	}

	memcpy(tfp->digest, measurement, tsem_digestsize());
	memcpy(digest->value, measurement, tsem_digestsize());
	digest->version = inode_query_iversion(inode);
	tsip->status = TSEM_INODE_COLLECTED;

 done:
	mutex_unlock(&tsip->mutex);
	return retn;
}

static void get_inode_cell(struct inode *inode, struct tsem_event *ep)
{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	ep->file.uid = from_kuid(ns, inode->i_uid);
	ep->file.gid = from_kgid(ns, inode->i_gid);
	ep->file.mode = inode->i_mode;
	ep->file.s_magic = inode->i_sb->s_magic;
	memcpy(ep->file.s_id, inode->i_sb->s_id, sizeof(ep->file.s_id));
	memcpy(ep->file.s_uuid, inode->i_sb->s_uuid.b,
	       sizeof(ep->file.s_uuid));
}

static void fill_inode(struct inode *inode, struct tsem_inode_cell *ip)
{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	ip->uid = from_kuid(ns, inode->i_uid);
	ip->gid = from_kgid(ns, inode->i_gid);
	ip->mode = inode->i_mode;
	ip->s_magic = inode->i_sb->s_magic;
	memcpy(ip->s_id, inode->i_sb->s_id, sizeof(ip->s_id));
	memcpy(ip->s_uuid, inode->i_sb->s_uuid.b, sizeof(ip->s_uuid));
}

static int get_file_cell(struct file *file, struct tsem_event *ep)
{
	int retn = 1;
	struct inode *inode = file_inode(file);

	inode_lock(inode);

	ep->pathname = get_path(&file->f_path);
	if (IS_ERR(ep->pathname)) {
		retn = PTR_ERR(ep->pathname);
		goto done;
	}

	retn = add_file_name(ep);
	if (retn)
		goto done;

	retn = add_file_digest(file, &ep->file);
	if (retn)
		goto done;

	get_inode_cell(inode, ep);
	retn = 0;

 done:
	inode_unlock(inode);
	return retn;
}

static int get_socket_accept(struct tsem_event *ep)
{
	char *p, path[UNIX_PATH_MAX + 1];
	int size, retn = 0;
	struct tsem_socket_accept_args *sap = &ep->CELL.socket_accept;

	if (sap->family == AF_INET || sap->family == AF_INET6)
		return retn;

	if (sap->family != AF_UNIX) {
		memcpy(sap->u.mapping, tsem_context(current)->zero_digest,
		       tsem_digestsize());
		return retn;
	}

	memset(path, '\0', sizeof(path));
	p = sap->u.af_unix->addr->name->sun_path;
	size = sap->u.af_unix->addr->len -
		offsetof(struct sockaddr_un, sun_path);
	strncpy(path, p, size);
	memcpy(sap->u.path, path, sizeof(sap->u.path));

	return retn;
}

static int get_socket_connect(struct tsem_socket_connect_args *scp)
{
	u8 *p;
	int retn, size;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	p = (u8 *) scp->addr->sa_data;
	size = scp->addr_len - offsetof(struct sockaddr, sa_data);
	retn = crypto_shash_digest(shash, p, size, scp->u.mapping);

 done:
	return retn;
}

static int get_socket_cell(struct tsem_event *ep)

{
	int size, retn = 0;
	struct tsem_socket_connect_args *scp = &ep->CELL.socket_connect;

	scp->family = scp->addr->sa_family;

	switch (scp->family) {
	case AF_INET:
		memcpy(&scp->u.ipv4, scp->addr, sizeof(scp->u.ipv4));
		break;
	case AF_INET6:
		memcpy(&scp->u.ipv6, scp->addr, sizeof(scp->u.ipv6));
		break;
	case AF_UNIX:
		memset(scp->u.path, '\0', sizeof(scp->u.path));
		size = scp->addr_len - offsetof(struct sockaddr_un, sun_path);
		strncpy(scp->u.path, scp->addr->sa_data, size);
		break;
	default:
		retn = get_socket_connect(scp);
		break;
	}

	return retn;
}

static int get_inode_getattr(struct tsem_inode_getattr_args *args,
			     struct tsem_event *ep)
{
	const struct path *path = args->path_arg;
	struct inode *inode = d_backing_inode(path->dentry);

	fill_inode(inode, &ep->CELL.inode_getattr.out.inode);
	return fill_path(path, &ep->CELL.inode_getattr.out.path);
}

static int get_inode_setattr(struct tsem_inode_setattr_args *args,
			     struct tsem_event *ep)
{
	int retn;
	struct user_namespace *ns;
	struct tsem_inode_setattr_args *sp;
	struct dentry *dentry = args->in.dentry;
	struct iattr *iattr = args->in.iattr;

	sp = &ep->CELL.inode_setattr;
	memset(sp, '\0', sizeof(*sp));

	retn = fill_path_dentry(dentry, &sp->out.path);
	if (retn)
		goto done;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	fill_inode(d_backing_inode(dentry), &sp->out.inode);

	sp->out.valid = iattr->ia_valid;
	if (sp->out.valid & ATTR_MODE)
		sp->out.mode = iattr->ia_mode;
	if (sp->out.valid & ATTR_UID)
		sp->out.uid = from_kuid(ns, iattr->ia_uid);
	if (sp->out.valid & ATTR_GID)
		sp->out.gid = from_kgid(ns, iattr->ia_gid);
	if (sp->out.valid & ATTR_SIZE)
		sp->out.size = iattr->ia_size;

 done:
	return retn;
}

static int get_inode_setxattr(struct tsem_inode_getxattr_args *args,
			      struct tsem_event *ep)
{
	int retn;
	const char *name = args->in.name;
	struct dentry *dentry = args->in.dentry;
	const void *value = args->in.value;
	size_t size = args->in.size;
	int flags = args->in.flags;
	struct tsem_inode_getxattr_args *ap = &ep->CELL.inode_getxattr;

	ap->out.size = size;
	ap->out.flags = flags;

	retn = fill_path_dentry(dentry, &ap->out.path);
	if (retn)
		return retn;

	fill_inode(dentry->d_inode, &ap->out.inode);

	ap->out.name = kstrdup(name, GFP_KERNEL);
	if (!ap->out.name) {
		retn = -ENOMEM;
		goto done;
	}

	ap->out.value = kmalloc(size, GFP_KERNEL);
	if (!ap->out.value)
		retn = -ENOMEM;
	memcpy(ap->out.value, value, size);

	ap->out.encoded_value = kzalloc(BASE64_CHARS(size) + 1, GFP_KERNEL);
	if (!ap->out.encoded_value) {
		retn = -ENOMEM;
		goto done;
	}
	base64_encode(ap->out.value, size, ap->out.encoded_value);

 done:
	if (retn) {
		kfree(ap->out.name);
		kfree(ap->out.value);
		kfree(ap->out.encoded_value);
	}
	return retn;
}

static int get_inode_getxattr(struct tsem_inode_getxattr_args *args,
			      struct tsem_event *ep)
{
	int retn = 0;
	const char *name = args->in.name;
	struct dentry *dentry = args->in.dentry;
	struct tsem_inode_getxattr_args *ap = &ep->CELL.inode_getxattr;

	retn = fill_path_dentry(dentry, &ap->out.path);
	if (retn)
		goto done;

	fill_inode(dentry->d_inode, &ap->out.inode);

	ap->out.name = kstrdup(name, GFP_KERNEL);
	if (!ap->out.name)
		retn = -ENOMEM;

 done:
	return retn;
}

static int get_inode_listxattr(struct tsem_inode_getxattr_args *args,
			       struct tsem_event *ep)
{
	int retn;
	struct dentry *dentry = args->in.dentry;
	struct tsem_inode_getxattr_args *ap = &ep->CELL.inode_getxattr;

	retn = fill_path_dentry(dentry, &ap->out.path);
	if (retn)
		return retn;

	fill_inode(dentry->d_inode, &ap->out.inode);
	return 0;
}

static int get_sb_pivotroot(struct tsem_sb_pivotroot_args *args,
			    struct tsem_event *ep)
{
	int retn;
	const struct path *old_path = args->in.old_path;
	const struct path *new_path = args->in.new_path;
	struct tsem_sb_pivotroot_args *ap = &ep->CELL.sb_pivotroot;

	retn = fill_path(old_path, &ap->out.old_path);
	if (!retn)
		retn = fill_path(new_path, &ap->out.new_path);

	return retn;
}

/**
 * tsem_event_init() - Initialize a security event description structure.
 * @event: The security event number for which the structure is being
 *	   initialized.
 * @params: A pointer to the aggregation structure used to hold the
 *	    parameters that describe the function.
 * @locked: A boolean flag used to indicate if the event to be
 *	    initialized is running in atomic context.
 *
 * This function is responsible for allocating and initializing the
 * primary tsem_event structure and populating it based on the event type.
 *
 * Return: This function returns a pointer to the allocated structure which
 *	   on failure will have an error return code embedded in it.
 */
struct tsem_event *tsem_event_init(enum tsem_event_type event,
				   struct tsem_event_parameters *params,
				   bool locked)
{
	int retn = 0;
	struct tsem_event *ep = NULL;
	struct tsem_task *task = tsem_task(current);

	ep = tsem_event_allocate(locked);
	if (!ep)
		return ERR_PTR(-ENOMEM);

	ep->event = event;
	ep->locked = locked;
	ep->pid = task_pid_nr(current);
	ep->instance = task->instance;
	ep->p_instance = task->p_instance;
	ep->timestamp = ktime_get_boottime_ns();
	memcpy(ep->comm, current->comm, sizeof(ep->comm));
	memcpy(ep->task_id, task->task_id, tsem_digestsize());
	memcpy(ep->p_task_id, task->p_task_id, tsem_digestsize());

	get_COE(&ep->COE);

	if (!params) {
		ep->no_params = true;
		goto done;
	}

	switch (event) {
	case TSEM_FILE_OPEN:
	case TSEM_BPRM_COMMITTING_CREDS:
		retn = get_file_cell(params->u.file, ep);
		break;
	case TSEM_MMAP_FILE:
		ep->CELL.mmap_file = *params->u.mmap_file;
		if (!ep->CELL.mmap_file.anonymous)
			retn = get_file_cell(ep->CELL.mmap_file.file, ep);
		break;
	case TSEM_SOCKET_CREATE:
		ep->CELL.socket_create = *params->u.socket_create;
		break;
	case TSEM_SOCKET_CONNECT:
	case TSEM_SOCKET_BIND:
		ep->CELL.socket_connect = *params->u.socket_connect;
		retn = get_socket_cell(ep);
		break;
	case TSEM_SOCKET_ACCEPT:
		ep->CELL.socket_accept = *params->u.socket_accept;
		retn = get_socket_accept(ep);
		break;
	case TSEM_TASK_KILL:
		ep->CELL.task_kill = *params->u.task_kill;
		break;
	case TSEM_INODE_GETATTR:
		retn = get_inode_getattr(params->u.inode_getattr, ep);
		break;
	case TSEM_INODE_SETATTR:
		retn = get_inode_setattr(params->u.inode_setattr, ep);
		break;
	case TSEM_INODE_SETXATTR:
		retn = get_inode_setxattr(params->u.inode_getxattr, ep);
		break;
	case TSEM_INODE_GETXATTR:
	case TSEM_INODE_REMOVEXATTR:
		retn = get_inode_getxattr(params->u.inode_getxattr, ep);
		break;
	case TSEM_INODE_LISTXATTR:
		retn = get_inode_listxattr(params->u.inode_getxattr, ep);
		break;
	case TSEM_SB_PIVOTROOT:
		retn = get_sb_pivotroot(params->u.sb_pivotroot, ep);
		break;
	default:
		WARN_ONCE(true, "Unhandled event type: %d\n", event);
		break;
	}

 done:
	if (retn) {
		kmem_cache_free(event_cachep, ep);
		ep = ERR_PTR(retn);
	} else
		kref_init(&ep->kref);

	return ep;
}

static void free_cell(struct tsem_event *ep)
{
	kfree(ep->pathname);

	switch (ep->event) {
	case TSEM_INODE_GETATTR:
		kfree(ep->CELL.inode_getattr.out.path.fstype);
		kfree(ep->CELL.inode_getattr.out.path.pathname);
		break;
	case TSEM_INODE_SETATTR:
		kfree(ep->CELL.inode_setattr.out.path.fstype);
		kfree(ep->CELL.inode_getattr.out.path.pathname);
		break;
	case TSEM_INODE_SETXATTR:
		kfree(ep->CELL.inode_getxattr.out.path.fstype);
		kfree(ep->CELL.inode_getxattr.out.path.pathname);
		kfree(ep->CELL.inode_getxattr.out.name);
		kfree(ep->CELL.inode_getxattr.out.encoded_value);
		break;
	case TSEM_INODE_GETXATTR:
	case TSEM_INODE_REMOVEXATTR:
		kfree(ep->CELL.inode_getxattr.out.path.fstype);
		kfree(ep->CELL.inode_getxattr.out.path.pathname);
		kfree(ep->CELL.inode_getxattr.out.name);
		break;
	case TSEM_INODE_LISTXATTR:
		kfree(ep->CELL.inode_getxattr.out.path.fstype);
		kfree(ep->CELL.inode_getxattr.out.path.pathname);
		break;
	case TSEM_SB_PIVOTROOT:
		kfree(ep->CELL.sb_pivotroot.out.old_path.fstype);
		kfree(ep->CELL.sb_pivotroot.out.old_path.pathname);
		kfree(ep->CELL.sb_pivotroot.out.new_path.fstype);
		kfree(ep->CELL.sb_pivotroot.out.new_path.pathname);
		break;
	default:
		break;
	}
}

/**
 * tsem_free_event() - Free a security event description.
 * @ep: A pointer to the security event description that is to be freed.
 *
 * This function is responsible for freeing the resources that were
 * allocated by the tsem_event_allocate() function.
 */
static void tsem_event_free(struct kref *kref)
{
	struct tsem_event *ep;

	ep = container_of(kref, struct tsem_event, kref);
	free_cell(ep);

	kmem_cache_free(event_cachep, ep);
}

/**
 * tsem_event_put() - Release a referenceto a TSEM event description.
 *
 * This function is called each time the use of a TSEM event description
 * is dropped.
 */
void tsem_event_put(struct tsem_event *ep)
{
	kref_put(&ep->kref, tsem_event_free);
}

/**
 * tsem_event_get() - Obtain a reference to a TSEM event description.
 *
 * This function is called on each invocation of the tsem_task_free
 * function to release one of the references on the TMA modeling
 * structure.
 */
void tsem_event_get(struct tsem_event *ep)
{
	kref_get(&ep->kref);
}

/**
 * tsem_event_allocate() - Allocate a TSEM event description structure.
 * @locked: A boolean flag used to indicate if the allocation is being
 *	    done in atomic context and must be serviced from the
 *	    pre-allocated event description structures.
 *
 * Return: This function returns a pointer to the allocated structure or
 *	   a NULL pointer in the event of an allocation failure.
 */
struct tsem_event *tsem_event_allocate(bool locked)
{
	unsigned int index;
	struct tsem_event *ep = NULL;
	struct tsem_context *ctx = tsem_context(current);

	if (!locked)
		return kmem_cache_zalloc(event_cachep, GFP_KERNEL);

	spin_lock(&ctx->magazine_lock);
	index = find_first_zero_bit(ctx->magazine_index, ctx->magazine_size);
	if (index < ctx->magazine_size) {
		ep = ctx->magazine[index];
		ctx->ws[index].index = index;
		ctx->ws[index].u.ctx = ctx;
		set_bit(index, ctx->magazine_index);

		/*
		 * Similar to the issue noted in the refill_event_magazine()
		 * function, this barrier is used to cause the consumption
		 * of the cache entry to become visible.

		 */
		smp_mb__after_atomic();
	}

	spin_unlock(&ctx->magazine_lock);

	if (ep) {
		INIT_WORK(&ctx->ws[index].work, refill_event_magazine);
		queue_work(system_wq, &ctx->ws[index].work);
		return ep;
	}

	pr_warn("tsem: %s in %llu failed event allocation, cache size=%u.\n",
		current->comm, tsem_context(current)->id, ctx->magazine_size);
	return NULL;
}

/**
 * tsem event_magazine_allocate() - Allocate a TSEM event magazine.
 * @ctx: A pointer to the modeling context that the magazine is
 *	 to be allocated for.
 * @size: The number of entries to be created in the magazine.

 * The security modeling event magazine is an array of tsem_event
 * structures that are used to service security hooks that are called
 * in atomic context.  Each modeling domain/namespace has a magazine
 * allocated to it and this function allocates and initializes the
 * memory structures needed to manage that magazine.

 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int tsem_event_magazine_allocate(struct tsem_context *ctx, size_t size)
{
	unsigned int lp;
	int retn = -ENOMEM;

	ctx->magazine_size = size;

	spin_lock_init(&ctx->magazine_lock);

	ctx->magazine_index = bitmap_zalloc(ctx->magazine_size, GFP_KERNEL);
	if (!ctx->magazine_index)
		return retn;

	ctx->magazine = kcalloc(ctx->magazine_size, sizeof(*ctx->magazine),
				GFP_KERNEL);
	if (!ctx->magazine)
		goto done;

	for (lp = 0; lp < ctx->magazine_size; ++lp) {
		ctx->magazine[lp] = kmem_cache_zalloc(event_cachep,
						      GFP_KERNEL);
		if (!ctx->magazine[lp])
			goto done;
	}

	ctx->ws = kcalloc(ctx->magazine_size, sizeof(*ctx->ws), GFP_KERNEL);
	if (ctx->ws)
		retn = 0;

 done:
	if (retn)
		tsem_event_magazine_free(ctx);

	return retn;
}

/**
 * tsem event_magazine_free() - Releases a TSEM event magazine.
 * @ctx: A pointer to the modeling context whose magazine is to be
 *	 released.
 *
 * The function is used to free the memory that was allocated by
 * the tsem_event_magazine_allocate() function for a security
 * modeling context.
 */
void tsem_event_magazine_free(struct tsem_context *ctx)
{
	unsigned int lp;

	for (lp = 0; lp < ctx->magazine_size; ++lp)
		kmem_cache_free(event_cachep, ctx->magazine[lp]);

	bitmap_free(ctx->magazine_index);
	kfree(ctx->ws);
	kfree(ctx->magazine);
}

/**
 * tsem event_cache_init() - Initialize the TSEM event cache.
 *
 * This function is called by the TSEM initialization function and sets
 * up the cache that will be used to allocate tsem_event structures.
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int __init tsem_event_cache_init(void)
{
	event_cachep = kmem_cache_create("tsem_event_cache",
					 sizeof(struct tsem_event), 0,
					 SLAB_PANIC, 0);
	if (!event_cachep)
		return -ENOMEM;

	return 0;
}
