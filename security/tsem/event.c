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
#include <linux/ipv6.h>
#include <uapi/linux/prctl.h>

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
	char *p, *p1, *pathbuffer = NULL;
	struct super_block *sb = dentry->d_sb;
	struct inode *inode = d_backing_inode(sb->s_root);

	if (MAJOR(sb->s_dev) || inode->i_op->rename)
		path->dev = sb->s_dev;
	else {
		if (dentry->d_op && dentry->d_op->d_dname) {
			pathbuffer = __getname();
			p = dentry->d_op->d_dname(dentry, pathbuffer, 4096);
			p1 = strchr(p, ':');
			if (p1)
				*p1 = '\0';
			path->pathname = kmalloc(strlen(p) + 3, GFP_KERNEL);
			if (IS_ERR(path->pathname)) {
				retn = PTR_ERR(path->pathname);
				goto done;
			}
			strcpy(path->pathname, p);
			strcat(path->pathname, ":/");
			__putname(pathbuffer);
		} else {
			p = "nodev:/";
			path->pathname = kmalloc(strlen(p) + 1, GFP_KERNEL);
			if (IS_ERR(path->pathname)) {
				retn = PTR_ERR(path->pathname);
				goto done;
			}
			strcpy(path->pathname, p);
		}
	}

 done:
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

	if (path->dev) {
		path->pathname = get_path(in);
		if (IS_ERR(path->pathname))
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
	if (IS_ERR(path->pathname))
		retn = PTR_ERR(path->pathname);

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

static int add_file_digest(struct file *file, struct tsem_file_args *args)
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
		retn = tsem_model_has_pseudonym(tsip, args->out.path.pathname);
		if (retn < 0)
			goto done;
		if (retn) {
			memcpy(args->out.digest, ctx->zero_digest,
			       tsem_digestsize());
			retn = 0;
			goto done;
		}
	}

	size = i_size_read(inode);
	if (!size) {
		memcpy(args->out.digest, ctx->zero_digest, tsem_digestsize());
		goto done;
	}

	digest = find_digest(tsip);

	if (digest && inode_eq_iversion(inode, digest->version) &&
	    tsip->status == TSEM_INODE_COLLECTED) {
		memcpy(args->out.digest, digest->value, tsem_digestsize());
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

	memcpy(args->out.digest, measurement, tsem_digestsize());
	memcpy(digest->value, measurement, tsem_digestsize());
	digest->version = inode_query_iversion(inode);
	tsip->status = TSEM_INODE_COLLECTED;

 done:
	mutex_unlock(&tsip->mutex);
	return retn;
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

static void fill_creds(const struct cred *cp, struct tsem_COE *tcp)
{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	tcp->uid = from_kuid(ns, cp->uid);
	tcp->euid = from_kuid(ns, cp->euid);
	tcp->suid = from_kuid(ns, cp->suid);

	tcp->gid = from_kgid(ns, cp->gid);
	tcp->egid = from_kgid(ns, cp->egid);
	tcp->sgid = from_kgid(ns, cp->sgid);

	tcp->fsuid = from_kuid(ns, cp->fsuid);
	tcp->fsgid = from_kgid(ns, cp->fsgid);

	tcp->capeff.mask = cp->cap_effective;

	tcp->securebits = cp->securebits;
}

static int get_inode_create(struct tsem_inode_args *args)
{
	int retn;
	struct inode *dir = args->in.dir;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dir, &args->out.dir);
	return 0;
}

static int get_inode_link(struct tsem_inode_args *args)
{
	int retn;
	struct inode *dir = args->in.dir;
	struct dentry *dentry = args->in.dentry;
	struct dentry *new_dentry = args->in.new_dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		goto done;

	retn = fill_path_dentry(new_dentry, &args->out.new_path);
	if (retn)
		goto done;

	fill_inode(dir, &args->out.dir);
	fill_inode(d_backing_inode(dentry), &args->out.inode);

 done:
	if (retn) {
		kfree(args->out.path.pathname);
		kfree(args->out.new_path.pathname);
	}

	return retn;
}

static int get_inode_symlink(struct tsem_inode_args *args)
{
	int retn;
	const char *old_name = args->in.old_name;
	struct inode *dir = args->in.dir;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dir, &args->out.dir);

	args->out.old_name = kstrdup(old_name, GFP_KERNEL);
	if (!args->out.old_name) {
		kfree(args->out.path.pathname);
		retn = -ENOMEM;
	}

	return retn;
}

static int get_inode_mknod(struct tsem_inode_args *args)
{
	int retn;
	struct inode *dir = args->in.dir;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dir, &args->out.dir);

	/*
	 * Set the UUID type of a RAMFS based filesystem to a common
	 * value in order to prevent the random generation of a UUID
	 * from perturbing the generaion of deterministic security
	 * state values.
	 */
	if (!strcmp(dir->i_sb->s_type->name, "tmpfs"))
		memset(args->out.dir.s_uuid, 0xff,
		       sizeof(args->out.dir.s_uuid));

	return 0;
}

static int get_inode_rename(struct tsem_inode_rename_args *args)
{
	int retn;
	struct inode *old_dir = args->in.old_dir;
	struct inode *new_dir = args->in.new_dir;
	struct dentry *old_dentry = args->in.old_dentry;
	struct dentry *new_dentry = args->in.new_dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(old_dentry, &args->out.old_path);
	if (retn)
		return retn;

	retn = fill_path_dentry(new_dentry, &args->out.new_path);
	if (retn) {
		kfree(args->out.old_path.pathname);
		return retn;
	}

	fill_inode(old_dir, &args->out.old_dir);
	fill_inode(new_dir, &args->out.new_dir);
	fill_inode(d_backing_inode(old_dentry), &args->out.inode);

	return 0;
}

static int get_inode_killpriv(struct tsem_inode_args *args)
{
	int retn;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(d_backing_inode(dentry), &args->out.inode);
	return 0;

}

static int get_file_cell(struct tsem_file_args *args)
{
	int retn = 1;
	struct file *file = args->in.file;
	struct inode *inode = file_inode(file);

	memset(&args->out, '\0', sizeof(args->out));
	inode_lock(inode);

	retn = fill_path(&file->f_path, &args->out.path);
	if (retn)
		goto done;

	args->out.flags = file->f_flags;
	fill_inode(inode, &args->out.inode);

	if (!S_ISREG(inode->i_mode))
		goto done;

	retn = add_file_digest(file, args);
	if (retn)
		kfree(args->out.path.pathname);

 done:
	inode_unlock(inode);
	return retn;
}

static void get_prlimit(struct tsem_task_prlimit_args *args)
{
	const struct cred *cred = args->in.cred;
	const struct cred *tcred = args->in.tcred;

	memset(&args->out, '\0', sizeof(args->out));

	fill_creds(cred, &args->out.cred);
	fill_creds(tcred, &args->out.tcred);
}

static void get_prctl(struct tsem_task_prctl_args *args)
{
	if (args->option == PR_SET_NAME || args->option == PR_GET_NAME)
		args->arg2 = 0;
}

static void get_socket(struct sock *sock, struct tsem_socket_create_args *args)
{
	args->family = sock->sk_family;
	args->type = sock->sk_type;
	args->protocol = sock->sk_protocol;
	args->kern = sock->sk_kern_sock;
	memcpy(args->owner, tsem_inode(SOCK_INODE(sock->sk_socket))->owner,
	       tsem_digestsize());
}

static int get_socket_address(struct tsem_socket_args *args,
			      struct sockaddr *addr)
{
	u8 *p;
	int retn, size;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	p = (u8 *) addr->sa_data;
	size = args->value - offsetof(struct sockaddr, sa_data);
	retn = crypto_shash_digest(shash, p, size, args->out.mapping);

 done:
	return retn;
}

static int get_socket_cell(struct tsem_socket_args *args)

{
	int size, retn = 0;
	struct sock *socka = args->in.socka;
	struct sockaddr *addr = args->in.addr;

	memset(&args->out, '\0', sizeof(args->out));

	get_socket(socka, &args->out.socka);

	switch (args->out.socka.family) {
	case AF_INET:
		memcpy(&args->out.ipv4, addr, sizeof(args->out.ipv4));
		break;
	case AF_INET6:
		memcpy(&args->out.ipv6, addr, sizeof(args->out.ipv6));
		break;
	case AF_UNIX:
		memset(args->out.path, '\0', sizeof(args->out.path));
		size = args->value - offsetof(struct sockaddr_un, sun_path);
		strncpy(args->out.path, addr->sa_data, size);
		break;
	default:
		retn = get_socket_address(args, addr);
		break;
	}

	return retn;
}

static void get_socket_accept(struct tsem_socket_args *args)
{
	char *p;
	int size;
	const struct in6_addr *ipv6;
	struct sock *socka = args->in.socka;

	memset(&args->out, '\0', sizeof(args->out));

	get_socket(socka, &args->out.socka);

	switch (args->out.socka.family) {
	case AF_INET:
		args->out.ipv4.sin_port = socka->sk_num;
		args->out.ipv4.sin_addr.s_addr = socka->sk_rcv_saddr;
		break;

	case AF_INET6:
		ipv6 = inet6_rcv_saddr(socka);
		if (ipv6) {
			args->out.ipv6.sin6_port = socka->sk_num;
			args->out.ipv6.sin6_addr = *ipv6;
		}
		break;

	case AF_UNIX:
		memset(args->out.path, '\0', sizeof(args->out.path));
		p = unix_sk(socka)->addr->name->sun_path;
		size = unix_sk(socka)->addr->len -
			offsetof(struct sockaddr_un, sun_path);
		strncpy(args->out.path, p, size);
		break;

	default:
		memcpy(args->out.mapping, tsem_context(current)->zero_digest,
		       tsem_digestsize());
		break;
	}
}

static void get_socket_pair(struct tsem_socket_args *args)
{
	struct sock *socka = args->in.socka;
	struct sock *sockb = args->in.sockb;

	memset(&args->out, '\0', sizeof(args->out));

	get_socket(socka, &args->out.socka);
	get_socket(sockb, &args->out.sockb);
}

static void get_socket_msg(struct tsem_socket_args *args)

{
	struct sock *socka = args->in.socka;
	void *addr = args->in.addr;

	memset(&args->out, '\0', sizeof(args->out));

	get_socket(socka, &args->out.socka);
	if (addr) {
		if (args->out.socka.family == AF_INET) {
			args->out.have_addr = true;
			args->out.ipv4 = *(struct sockaddr_in *) addr;
		}
		if (args->out.socka.family == AF_INET6) {
			args->out.have_addr = true;
			args->out.ipv6 = *(struct sockaddr_in6 *) addr;
		}
	}
}

static void get_socket_argument(struct tsem_socket_args *args)

{
	struct sock *socka = args->in.socka;

	memset(&args->out, '\0', sizeof(args->out));
	get_socket(socka, &args->out.socka);
}

static int get_inode_getattr(struct tsem_inode_attr_args *args)
{
	const struct path *path = args->in.path;
	struct inode *inode = d_backing_inode(path->dentry);

	memset(&args->out, '\0', sizeof(args->out));
	fill_inode(inode, &args->out.inode);
	return fill_path(path, &args->out.path);
}

static int get_inode_setattr(struct tsem_inode_attr_args *args)
{
	int retn;
	struct user_namespace *ns;
	struct dentry *dentry = args->in.dentry;
	struct iattr *iattr = args->in.iattr;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		goto done;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	fill_inode(d_backing_inode(dentry), &args->out.inode);

	args->out.valid = iattr->ia_valid;
	if (args->out.valid & ATTR_MODE)
		args->out.mode = iattr->ia_mode;
	if (args->out.valid & ATTR_UID)
		args->out.uid = from_kuid(ns, iattr->ia_uid);
	if (args->out.valid & ATTR_GID)
		args->out.gid = from_kgid(ns, iattr->ia_gid);
	if (args->out.valid & ATTR_SIZE)
		args->out.size = iattr->ia_size;

 done:
	return retn;
}

static int get_inode_setxattr(struct tsem_inode_xattr_args *args)
{
	int retn;
	const char *name = args->in.name;
	struct dentry *dentry = args->in.dentry;
	const void *value = args->in.value;
	size_t size = args->in.size;
	int flags = args->in.flags;

	memset(&args->out, '\0', sizeof(args->out));

	args->out.size = size;
	args->out.flags = flags;

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dentry->d_inode, &args->out.inode);

	args->out.name = kstrdup(name, GFP_KERNEL);
	if (!args->out.name) {
		retn = -ENOMEM;
		goto done;
	}

	args->out.value = kmalloc(size, GFP_KERNEL);
	if (!args->out.value)
		retn = -ENOMEM;
	memcpy(args->out.value, value, size);

	args->out.encoded_value = kzalloc(BASE64_CHARS(size) + 1, GFP_KERNEL);
	if (!args->out.encoded_value) {
		retn = -ENOMEM;
		goto done;
	}
	base64_encode(args->out.value, size, args->out.encoded_value);

 done:
	if (retn) {
		kfree(args->out.name);
		kfree(args->out.value);
		kfree(args->out.encoded_value);
	}
	return retn;
}

static int get_inode_getxattr(struct tsem_inode_xattr_args *args)
{
	int retn;
	const char *name = args->in.name;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dentry->d_inode, &args->out.inode);

	args->out.name = kstrdup(name, GFP_KERNEL);
	if (!args->out.name)
		retn = -ENOMEM;

	if (retn)
		kfree(args->out.name);
	return retn;
}

static int get_inode_listxattr(struct tsem_inode_xattr_args *args)
{
	int retn;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return retn;

	fill_inode(dentry->d_inode, &args->out.inode);
	return 0;
}

static int get_kernel_module(struct tsem_kernel_args *args)
{
	int retn = 0;
	char *kmod_name = args->in.kmod_name;

	memset(&args->out, '\0', sizeof(args->out));

	args->out.kmod_name = kstrdup(kmod_name, GFP_KERNEL);
	if (!args->out.kmod_name)
		retn = -ENOMEM;

	args->out.kmod_name = kstrdup(kmod_name, GFP_KERNEL);
	if (!args->out.kmod_name)
		retn = -ENOMEM;

	return retn;
}

static int get_kernel_file(struct tsem_kernel_args *args)
{
	int retn = 0;
	struct file *file = args->in.file;
	struct inode *inode = file_inode(file);

	memset(&args->out, '\0', sizeof(args->out));
	inode_lock(inode);

	retn = fill_path(&file->f_path, &args->out.file.out.path);
	if (retn)
		goto done;

	args->out.file.out.flags = file->f_flags;
	fill_inode(inode, &args->out.file.out.inode);

	if (!S_ISREG(inode->i_mode))
		goto done;

	retn = add_file_digest(file, &args->out.file);
	if (retn)
		kfree(args->out.file.out.path.pathname);

 done:
	inode_unlock(inode);
	return retn;
}

static int get_sb_mount(struct tsem_sb_args *args)
{
	int retn = -ENOMEM;
	const char *dev_name = args->in.dev_name;
	const char *type = args->in.type;
	const struct path *path = args->in.path;

	memset(&args->out, '\0', sizeof(args->out));

	if (dev_name) {
		args->out.dev_name = kstrdup(dev_name, GFP_KERNEL);
		if (!args->out.dev_name)
			goto done;
	}

	if (type) {
		args->out.type = kstrdup(type, GFP_KERNEL);
		if (!args->out.type)
			goto done;
	}

	retn = fill_path(path, &args->out.path);

 done:
	if (retn) {
		kfree(args->out.dev_name);
		kfree(args->out.type);
	}
	return retn;
}

static int get_sb_umount(struct tsem_sb_args *args)
{
	int retn;
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return -ENOMEM;

	fill_inode(d_backing_inode(dentry), &args->out.inode);
	return 0;
}

static int get_sb_remount(struct tsem_sb_args *args)
{
	int retn = -ENOMEM;
	struct super_block *sb = args->in.sb;

	memset(&args->out, '\0', sizeof(args->out));

	args->flags = sb->s_flags;

	args->out.type = kstrdup(sb->s_type->name, GFP_KERNEL);
	if (!args->out.type)
		goto done;

	fill_inode(d_backing_inode(sb->s_root), &args->out.inode);
	retn = fill_path_dentry(sb->s_root, &args->out.path);

 done:
	if (retn) {
		kfree(args->out.type);
		kfree(args->out.path.pathname);
	}

	return retn;
}

static void get_netlink(struct tsem_netlink_args *args)
{
	struct sock *sock = args->in.sock;
	struct netlink_skb_parms *np = args->in.parms;
	struct user_namespace *ns;

	memset(&args->out, '\0', sizeof(args->out));
	get_socket(sock, &args->out.sock);

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;
	args->out.uid = from_kuid(ns, np->creds.uid);
	args->out.gid = from_kgid(ns, np->creds.gid);

	args->out.portid = np->portid;
	args->out.dst_group = np->dst_group;
	args->out.flags = np->flags;
	args->out.nsid_set = np->nsid_is_set;
	args->out.nsid = np->nsid;
}

static void get_ipc_cred(struct kern_ipc_perm *perm, struct tsem_ipc_perm *tp)
{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	tp->uid = from_kuid(ns, perm->uid);
	tp->gid = from_kgid(ns, perm->gid);
	tp->cuid = from_kuid(ns, perm->cuid);
	tp->cgid = from_kgid(ns, perm->cgid);
	tp->mode = perm->mode;
}

static void get_ipc_permission(struct tsem_ipc_args *args)
{
	struct kern_ipc_perm *perm = args->in.perm;

	memset(&args->out, '\0', sizeof(args->out));

	get_ipc_cred(perm, &args->out.perm);
	memcpy(args->out.owner, tsem_ipc(perm)->owner, tsem_digestsize());
}

static void get_msg_queue_msgrcv(struct tsem_ipc_args *args)
{
	struct kern_ipc_perm *perm = args->in.perm;
	struct tsem_task *target = tsem_task(args->in.target);

	memset(&args->out, '\0', sizeof(args->out));

	get_ipc_cred(perm, &args->out.perm);
	memcpy(args->out.owner, tsem_ipc(perm)->owner, tsem_digestsize());
	memcpy(args->out.target, target->task_id, tsem_digestsize());
}

static void get_key_alloc(struct tsem_key_args *args)
{
	const struct cred *cred = args->in.cred;

	memset(&args->out, '\0', sizeof(args->out));
	fill_creds(cred, &args->out.cred);
}

static void get_key_perm(struct tsem_key_args *args)
{
	const struct cred *cred = args->in.cred;
	struct user_namespace *ns;
	const key_ref_t ref = args->in.ref;
	struct key *key = key_ref_to_ptr(ref);

	memset(&args->out, '\0', sizeof(args->out));
	fill_creds(cred, &args->out.cred);

	args->out.possessed = is_key_possessed(ref);

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;
	args->out.uid = from_kuid(ns, key->uid);
	args->out.gid = from_kgid(ns, key->gid);

	args->out.perm = key->perm;
	args->out.flags = key->flags;
}

static int get_sb_statfs(struct tsem_sb_args *args)
{
	int retn;
	struct dentry *dentry = args->in.dentry;

	retn = fill_path_dentry(dentry, &args->out.path);
	if (retn)
		return -ENOMEM;

	fill_inode(dentry->d_inode, &args->out.inode);
	return 0;
}

static int get_move_mount(struct tsem_sb_args *args)
{
	int retn;
	const struct path *old_path = args->in.path;
	const struct path *new_path = args->in.path2;

	memset(&args->out, '\0', sizeof(args->out));

	retn = fill_path(old_path, &args->out.path);
	if (!retn)
		retn = fill_path(new_path, &args->out.path2);

	return retn;
}

static int get_quotactl(struct tsem_quota_args *args)
{
	int retn;
	struct super_block *sb = args->in.sb;

	memset(&args->out, '\0', sizeof(args->out));

	args->out.s_flags = sb->s_flags;

	args->out.fstype = kstrdup(sb->s_type->name, GFP_KERNEL);
	if (!args->out.fstype)
		goto done;

	fill_inode(d_backing_inode(sb->s_root), &args->out.inode);
	retn = fill_path_dentry(sb->s_root, &args->out.path);

 done:
	if (retn)
		kfree(args->out.fstype);
	return retn;
}

static int get_quotaon(struct tsem_quota_args *args)
{
	struct dentry *dentry = args->in.dentry;

	memset(&args->out, '\0', sizeof(args->out));

	fill_inode(d_backing_inode(dentry), &args->out.inode);
	return fill_path_dentry(dentry, &args->out.path);
}

/**
 * tsem_event_init() - Initialize a security event description structure.
 * @ep: A pointer to the tsem_event structure that describes the
 *	security event.
 *
 * This function is responsible for initializing the tsem_event structure
 * and populating it based on the event type.
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int tsem_event_init(struct tsem_event *ep)
{
	int retn = 0;
	struct tsem_task *task = tsem_task(current);

	ep->pid = task_pid_nr(current);
	ep->instance = task->instance;
	ep->p_instance = task->p_instance;
	ep->timestamp = ktime_get_boottime_ns();
	memcpy(ep->comm, current->comm, sizeof(ep->comm));
	memcpy(ep->task_id, task->task_id, tsem_digestsize());
	memcpy(ep->p_task_id, task->p_task_id, tsem_digestsize());

	get_COE(&ep->COE);

	if (ep->no_params)
		goto done;

	switch (ep->event) {
	case TSEM_NETLINK_SEND:
		get_netlink(&ep->CELL.netlink);
		break;
	case TSEM_IPC_PERMISSION:
	case TSEM_SHM_ASSOCIATE:
	case TSEM_SHM_SHMCTL:
	case TSEM_SHM_SHMAT:
	case TSEM_SEM_ASSOCIATE:
	case TSEM_SEM_SEMCTL:
	case TSEM_SEM_SEMOP:
	case TSEM_MSG_QUEUE_ASSOCIATE:
	case TSEM_MSG_QUEUE_MSGCTL:
	case TSEM_MSG_QUEUE_MSGSND:
		get_ipc_permission(&ep->CELL.ipc);
		break;
	case TSEM_MSG_QUEUE_MSGRCV:
		get_msg_queue_msgrcv(&ep->CELL.ipc);
		break;
	case TSEM_KEY_ALLOC:
		get_key_alloc(&ep->CELL.key);
		break;
	case TSEM_KEY_PERMISSION:
		get_key_perm(&ep->CELL.key);
		break;
	case TSEM_INODE_CREATE:
	case TSEM_INODE_MKDIR:
	case TSEM_INODE_RMDIR:
	case TSEM_INODE_UNLINK:
		retn = get_inode_create(&ep->CELL.inode);
		break;
	case TSEM_INODE_LINK:
		retn = get_inode_link(&ep->CELL.inode);
		break;
	case TSEM_INODE_SYMLINK:
		retn = get_inode_symlink(&ep->CELL.inode);
		break;
	case TSEM_INODE_MKNOD:
		retn = get_inode_mknod(&ep->CELL.inode);
		break;
	case TSEM_INODE_RENAME:
		retn = get_inode_rename(&ep->CELL.inode_rename);
		break;
	case TSEM_INODE_KILLPRIV:
		retn = get_inode_killpriv(&ep->CELL.inode);
		break;
	case TSEM_FILE_OPEN:
	case TSEM_BPRM_COMMITTING_CREDS:
	case TSEM_FILE_IOCTL:
	case TSEM_FILE_LOCK:
	case TSEM_FILE_FCNTL:
	case TSEM_FILE_RECEIVE:
		retn = get_file_cell(&ep->CELL.file);
		break;
	case TSEM_MMAP_FILE:
		if (!ep->CELL.mmap_file.anonymous)
			retn = get_file_cell(&ep->CELL.mmap_file.file);
		break;
	case TSEM_TASK_PRLIMIT:
		get_prlimit(&ep->CELL.task_prlimit);
		break;
	case TSEM_TASK_PRCTL:
		get_prctl(&ep->CELL.task_prctl);
		break;
	case TSEM_UNIX_STREAM_CONNECT:
	case TSEM_UNIX_MAY_SEND:
	case TSEM_SOCKET_SOCKETPAIR:
		get_socket_pair(&ep->CELL.socket);
		break;
	case TSEM_SOCKET_CONNECT:
	case TSEM_SOCKET_BIND:
		retn = get_socket_cell(&ep->CELL.socket);
		break;
	case TSEM_SOCKET_ACCEPT:
		get_socket_accept(&ep->CELL.socket);
		break;
	case TSEM_SOCKET_LISTEN:
	case TSEM_SOCKET_GETSOCKNAME:
	case TSEM_SOCKET_GETPEERNAME:
	case TSEM_SOCKET_SETSOCKOPT:
	case TSEM_SOCKET_SHUTDOWN:
	case TSEM_TUN_DEV_ATTACH_QUEUE:
		get_socket_argument(&ep->CELL.socket);
		break;
	case TSEM_SOCKET_SENDMSG:
	case TSEM_SOCKET_RECVMSG:
		get_socket_msg(&ep->CELL.socket);
		break;
	case TSEM_INODE_GETATTR:
		retn = get_inode_getattr(&ep->CELL.inode_attr);
		break;
	case TSEM_INODE_SETATTR:
		retn = get_inode_setattr(&ep->CELL.inode_attr);
		break;
	case TSEM_INODE_SETXATTR:
		retn = get_inode_setxattr(&ep->CELL.inode_xattr);
		break;
	case TSEM_INODE_GETXATTR:
	case TSEM_INODE_REMOVEXATTR:
		retn = get_inode_getxattr(&ep->CELL.inode_xattr);
		break;
	case TSEM_INODE_LISTXATTR:
		retn = get_inode_listxattr(&ep->CELL.inode_xattr);
		break;
	case TSEM_KERNEL_MODULE_REQUEST:
		retn = get_kernel_module(&ep->CELL.kernel);
		break;
	case TSEM_KERNEL_READ_FILE:
		retn = get_kernel_file(&ep->CELL.kernel);
		break;
	case TSEM_SB_MOUNT:
		retn = get_sb_mount(&ep->CELL.sb);
		break;
	case TSEM_SB_UMOUNT:
		retn = get_sb_umount(&ep->CELL.sb);
		break;
	case TSEM_SB_REMOUNT:
		retn = get_sb_remount(&ep->CELL.sb);
		break;
	case TSEM_SB_STATFS:
		retn = get_sb_statfs(&ep->CELL.sb);
		break;
	case TSEM_SB_PIVOTROOT:
	case TSEM_MOVE_MOUNT:
		retn = get_move_mount(&ep->CELL.sb);
		break;
	case TSEM_QUOTACTL:
		retn = get_quotactl(&ep->CELL.quota);
		break;
	case TSEM_QUOTA_ON:
		retn = get_quotaon(&ep->CELL.quota);
		break;
	default:
		break;
	}

 done:
	if (retn)
		kmem_cache_free(event_cachep, ep);
	else
		kref_init(&ep->kref);

	return retn;
}

static void free_cell(struct tsem_event *ep)
{
	switch (ep->event) {
	case TSEM_KERNEL_MODULE_REQUEST:
		kfree(ep->CELL.kernel.out.kmod_name);
		break;
	case TSEM_KERNEL_READ_FILE:
		kfree(ep->CELL.kernel.out.file.out.path.pathname);
		break;
	case TSEM_INODE_CREATE:
	case TSEM_INODE_MKDIR:
	case TSEM_INODE_RMDIR:
	case TSEM_INODE_UNLINK:
	case TSEM_INODE_MKNOD:
	case TSEM_INODE_KILLPRIV:
		kfree(ep->CELL.inode.out.path.pathname);
		break;
	case TSEM_INODE_LINK:
		kfree(ep->CELL.inode.out.path.pathname);
		kfree(ep->CELL.inode.out.new_path.pathname);
		break;
	case TSEM_INODE_SYMLINK:
		kfree(ep->CELL.inode.out.old_name);
		kfree(ep->CELL.inode.out.path.pathname);
		break;
	case TSEM_INODE_RENAME:
		kfree(ep->CELL.inode_rename.out.old_path.pathname);
		kfree(ep->CELL.inode_rename.out.new_path.pathname);
		break;
	case TSEM_FILE_OPEN:
	case TSEM_BPRM_COMMITTING_CREDS:
	case TSEM_MMAP_FILE:
	case TSEM_FILE_IOCTL:
	case TSEM_FILE_LOCK:
	case TSEM_FILE_FCNTL:
	case TSEM_FILE_RECEIVE:
		kfree(ep->CELL.file.out.path.pathname);
		break;
	case TSEM_INODE_GETATTR:
	case TSEM_INODE_SETATTR:
		kfree(ep->CELL.inode_attr.out.path.pathname);
		break;
	case TSEM_INODE_SETXATTR:
	case TSEM_INODE_GETXATTR:
	case TSEM_INODE_REMOVEXATTR:
	case TSEM_INODE_LISTXATTR:
		kfree(ep->CELL.inode_xattr.out.path.pathname);
		kfree(ep->CELL.inode_xattr.out.name);
		kfree(ep->CELL.inode_xattr.out.value);
		kfree(ep->CELL.inode_xattr.out.encoded_value);
		break;
	case TSEM_SB_MOUNT:
		kfree(ep->CELL.sb.out.dev_name);
		kfree(ep->CELL.sb.out.type);
		kfree(ep->CELL.sb.out.path.pathname);
		break;
	case TSEM_SB_UMOUNT:
		kfree(ep->CELL.sb.out.path.pathname);
		break;
	case TSEM_SB_REMOUNT:
		kfree(ep->CELL.sb.out.type);
		kfree(ep->CELL.sb.out.path.pathname);
		break;
	case TSEM_SB_PIVOTROOT:
	case TSEM_MOVE_MOUNT:
		kfree(ep->CELL.sb.out.path.pathname);
		kfree(ep->CELL.sb.out.path2.pathname);
		break;
	case TSEM_QUOTACTL:
		kfree(ep->CELL.quota.out.fstype);
		kfree(ep->CELL.quota.out.path.pathname);
		break;
	case TSEM_QUOTA_ON:
		kfree(ep->CELL.quota.out.path.pathname);
		break;
	case TSEM_SB_STATFS:
		kfree(ep->CELL.sb.out.path.pathname);
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
struct tsem_event *tsem_event_allocate(enum tsem_event_type event, bool locked)
{
	unsigned int index;
	struct tsem_event *ep = NULL;
	struct tsem_context *ctx = tsem_context(current);

	if (!locked) {
		ep = kmem_cache_zalloc(event_cachep, GFP_KERNEL);
		if (ep)
			ep->event = event;
		return ep;
	}

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
		ep->event = event;
		ep->locked = true;
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
