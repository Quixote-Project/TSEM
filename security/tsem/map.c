// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file implements mapping of events into security event points.
 */

#include "tsem.h"

static int get_COE_mapping(struct tsem_event *ep, u8 *mapping)
{
	int retn = 0, size;
	u8 *p;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.uid;
	size = sizeof(ep->COE.uid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.euid;
	size = sizeof(ep->COE.euid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.suid;
	size = sizeof(ep->COE.suid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.gid;
	size = sizeof(ep->COE.gid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.egid;
	size = sizeof(ep->COE.egid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.sgid;
	size = sizeof(ep->COE.sgid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.fsuid;
	size = sizeof(ep->COE.fsuid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.fsgid;
	size = sizeof(ep->COE.fsgid);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) &ep->COE.capeff;
	size = sizeof(ep->COE.capeff);
	retn = crypto_shash_finup(shash, p, size, mapping);

 done:
	return retn;
}

static int add_u16(struct shash_desc *shash, u16 value)
{
	return crypto_shash_update(shash, (char *) &value, sizeof(value));
}

static int add_u32(struct shash_desc *shash, u32 value)
{
	return crypto_shash_update(shash, (char *) &value, sizeof(value));
}

static int add_u64(struct shash_desc *shash, u64 value)
{
	return crypto_shash_update(shash, (char *) &value, sizeof(value));
}

static int add_str(struct shash_desc *shash, char *str)
{
	u32 value;
	u8 *p;
	int retn;
	int size;

	p = (u8 *) &value;
	value = strlen(str);
	size = sizeof(value);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) str;
	size = strlen(str);
	retn = crypto_shash_update(shash, p, size);

 done:
	return retn;
}

static int add_path(struct shash_desc *shash, struct tsem_path *path)
{
	int retn;

	if (path->dev) {
		retn = add_u32(shash, MAJOR(path->dev));
		if (retn)
			goto done;
		retn = add_u32(shash, MINOR(path->dev));
		if (retn)
			goto done;
	}

	retn = add_str(shash, path->pathname);

 done:
	return retn;
}

static int add_inode(struct shash_desc *shash, struct tsem_inode_cell *inode)
{
	u32 value;
	u8 *p = (u8 *) &value;
	int retn;
	int size = sizeof(value);

	value = inode->uid;
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	value = inode->gid;
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	value = inode->mode;
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	value = inode->s_magic;
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) inode->s_id;
	size = sizeof(inode->s_id);
	retn = crypto_shash_update(shash, p, size);
	if (retn)
		goto done;

	p = (u8 *) inode->s_uuid;
	size = sizeof(inode->s_uuid);
	retn = crypto_shash_update(shash, p, size);

 done:
	return retn;
}

static int add_file(struct shash_desc *shash, struct tsem_file_args *args)
{
	int retn;

	retn = add_u32(shash, args->out.flags);
	if (retn)
		goto done;

	retn = add_inode(shash, &args->out.inode);
	if (retn)
		goto done;

	retn = add_path(shash, &args->out.path);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, args->out.digest, tsem_digestsize());

 done:
	return retn;
}

static int add_creds(struct shash_desc *shash, struct tsem_COE *cp)
{
	int retn;

	retn = add_u32(shash, cp->uid);
	if (!retn)
		goto done;

	retn = add_u32(shash, cp->euid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->suid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->gid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->egid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->sgid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->fsuid);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->fsgid);
	if (retn)
		goto done;

	retn = add_u64(shash, cp->capeff.value);
	if (retn)
		goto done;

	retn = add_u32(shash, cp->securebits);

 done:
	return retn;
}

static int add_socket(struct shash_desc *shash,
		      struct tsem_socket_create_args *args)
{
	int retn;

	retn = add_u32(shash, args->family);
	if (retn)
		goto done;

	retn = add_u32(shash, args->type);
	if (retn)
		goto done;

	retn = add_u32(shash, args->protocol);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, args->owner, sizeof(args->owner));

 done:
	return retn;
}

static int get_cell_mapping(struct tsem_event *ep, u8 *mapping)
{
	int retn = 0, size;
	u8 *p;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	struct tsem_socket_connect_args *scp = &ep->CELL.socket_connect;
	struct tsem_socket_accept_args *sap = &ep->CELL.socket_accept;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	switch (ep->event) {
	case TSEM_NETLINK_SEND:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.netlink.out.uid);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.netlink.out.gid);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.netlink.out.portid);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.netlink.out.dst_group);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.netlink.out.flags);
		if (retn)
			goto done;

		if (ep->CELL.netlink.out.nsid_set) {
			retn = add_u32(shash, ep->CELL.netlink.out.flags);
			if (retn)
				goto done;
		}

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_CREATE:
	case TSEM_INODE_MKDIR:
		retn = add_inode(shash, &ep->CELL.inode.out.dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = add_u16(shash, ep->CELL.inode.mode);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_RMDIR:
	case TSEM_INODE_UNLINK:
		retn = add_inode(shash, &ep->CELL.inode.out.dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SYSLOG:
		retn = add_u32(shash, ep->CELL.value);
		if (retn)
			break;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SETTIME:
		retn = add_u64(shash, ep->CELL.time.seconds);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.time.nsecs);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.time.minuteswest);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.time.dsttime);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_LINK:
		retn = add_inode(shash, &ep->CELL.inode.out.dir);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode.out.inode);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.new_path);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_SYMLINK:
		retn = add_inode(shash, &ep->CELL.inode.out.dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = add_str(shash, ep->CELL.inode.out.old_name);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_MKNOD:
		retn = add_inode(shash, &ep->CELL.inode.out.dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = add_u16(shash, ep->CELL.inode.mode);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode.dev);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_RENAME:
		retn = add_inode(shash, &ep->CELL.inode_rename.out.inode);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode_rename.out.old_dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode_rename.out.old_path);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode_rename.out.new_dir);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode_rename.out.new_path);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_KILLPRIV:
		retn = add_inode(shash, &ep->CELL.inode.out.inode);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.inode.out.path);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_FILE_OPEN:
	case TSEM_BPRM_COMMITTING_CREDS:
		retn = add_file(shash, &ep->CELL.file);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		if (retn)
			goto done;
		break;

	case TSEM_FILE_IOCTL:
	case TSEM_FILE_LOCK:
	case TSEM_FILE_FCNTL:
		retn = add_file(shash, &ep->CELL.file);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.file.cmd);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_FILE_RECEIVE:
		retn = add_file(shash, &ep->CELL.file);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_MMAP_FILE:
		retn = add_u32(shash, ep->CELL.mmap_file.reqprot);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.mmap_file.prot);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.mmap_file.flags);
		if (retn)
			goto done;

		if (!ep->CELL.mmap_file.anonymous) {
			retn = add_file(shash, &ep->CELL.mmap_file.file);
			if (retn)
				goto done;
		}

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_UNIX_STREAM_CONNECT:
	case TSEM_UNIX_MAY_SEND:
	case TSEM_SOCKET_SOCKETPAIR:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		retn = add_socket(shash, &ep->CELL.socket.out.sockb);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SOCKET_SENDMSG:
	case TSEM_SOCKET_RECVMSG:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		if (!ep->CELL.socket.out.have_addr) {
			retn = crypto_shash_final(shash, mapping);
			goto done;
		}

		if (ep->CELL.socket.out.socka.family == AF_INET) {
			ipv4 = &ep->CELL.socket.out.ipv4;
			retn = add_u16(shash, ipv4->sin_port);
			if (retn)
				goto done;

			retn = add_u32(shash, ipv4->sin_addr.s_addr);
			if (retn)
				goto done;
		}
		if (ep->CELL.socket.out.socka.family == AF_INET6) {
			ipv6 = &ep->CELL.socket.out.ipv6;
			retn = add_u16(shash, ipv6->sin6_port);
			if (retn)
				goto done;

			p = (u8 *) &ipv6->sin6_addr.in6_u.u6_addr8;
			size = sizeof(ipv6->sin6_addr.in6_u.u6_addr8);
			retn = crypto_shash_update(shash, p, size);
			if (retn)
				goto done;
		}

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SOCKET_GETSOCKNAME:
	case TSEM_SOCKET_GETPEERNAME:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SOCKET_CREATE:
		p = (u8 *) &ep->CELL.socket_create.family;
		size = sizeof(ep->CELL.socket_create.family);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &ep->CELL.socket_create.type;
		size = sizeof(ep->CELL.socket_create.type);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &ep->CELL.socket_create.protocol;
		size = sizeof(ep->CELL.socket_create.protocol);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &ep->CELL.socket_create.kern;
		size = sizeof(ep->CELL.socket_create.kern);
		retn = crypto_shash_finup(shash, p, size, mapping);
		if (retn)
			goto done;
		break;

	case TSEM_SOCKET_CONNECT:
	case TSEM_SOCKET_BIND:
		p = (u8 *) &scp->family;
		size = sizeof(scp->family);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		switch (scp->family) {
		case AF_INET:
			ipv4 = (struct sockaddr_in *) &scp->u.ipv4;
			p = (u8 *) &ipv4->sin_port;
			size = sizeof(ipv4->sin_port);
			retn = crypto_shash_update(shash, p, size);
			if (retn)
				goto done;

			p = (u8 *) &ipv4->sin_addr.s_addr;
			size = sizeof(ipv4->sin_addr.s_addr);
			retn = crypto_shash_finup(shash, p, size, mapping);
			break;

		case AF_INET6:
			ipv6 = (struct sockaddr_in6 *) &scp->u.ipv6;
			p = (u8 *) &ipv6->sin6_port;
			size = sizeof(ipv6->sin6_port);
			retn = crypto_shash_update(shash, p, size);
			if (retn)
				goto done;

			p = (u8 *) ipv6->sin6_addr.in6_u.u6_addr8;
			size = sizeof(ipv6->sin6_addr.in6_u.u6_addr8);
			retn = crypto_shash_update(shash, p, size);
			if (retn)
				goto done;

			p = (u8 *) &ipv6->sin6_flowinfo;
			size = sizeof(ipv6->sin6_flowinfo);
			retn = crypto_shash_update(shash, p, size);
			if (retn)
				goto done;

			p = (u8 *) &ipv6->sin6_scope_id;
			size = sizeof(ipv6->sin6_scope_id);
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;

		case AF_UNIX:
			p = scp->u.path;
			size = strlen(scp->u.path);
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;

		default:
			p = (u8 *) scp->u.mapping;
			size = tsem_digestsize();
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;
		}
		break;

	case TSEM_SOCKET_ACCEPT:
		p = (u8 *) &sap->family;
		size = sizeof(sap->family);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &sap->type;
		size = sizeof(sap->type);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &sap->port;
		size = sizeof(sap->port);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		switch (sap->family) {
		case AF_INET:
			p = (u8 *) &sap->u.ipv4;
			size = sizeof(sap->u.ipv4);
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;

		case AF_INET6:
			p = (u8 *) sap->u.ipv6.in6_u.u6_addr8;
			size = sizeof(sap->u.ipv6.in6_u.u6_addr8);
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;

		case AF_UNIX:
			p = sap->u.path;
			size = strlen(sap->u.path);
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;

		default:
			p = sap->u.mapping;
			size = tsem_digestsize();
			retn = crypto_shash_finup(shash, p, size, mapping);
			if (retn)
				goto done;
			break;
		}
		break;

	case TSEM_SOCKET_LISTEN:
	case TSEM_SOCKET_SHUTDOWN:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.socket.value);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SOCKET_SETSOCKOPT:
		retn = add_socket(shash, &ep->CELL.socket.out.socka);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.socket.value);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.socket.optname);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_KERNEL_MODULE_REQUEST:
		retn = add_str(shash, ep->CELL.kernel.out.kmod_name);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_KERNEL_LOAD_DATA:
		retn = add_u32(shash, ep->CELL.kernel.id);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.kernel.contents);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_KERNEL_READ_FILE:
		retn = add_file(shash, &ep->CELL.kernel.out.file);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.kernel.id);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.kernel.contents);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_TASK_KILL:
		p = (u8 *) &ep->CELL.task_kill.cross_model;
		size = sizeof(ep->CELL.task_kill.cross_model);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &ep->CELL.task_kill.signal;
		size = sizeof(ep->CELL.task_kill.signal);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = (u8 *) &ep->CELL.task_kill.target;
		size = sizeof(ep->CELL.task_kill.target);
		retn = crypto_shash_finup(shash, p, size, mapping);
		if (retn)
			goto done;
		break;

	case TSEM_PTRACE_TRACEME:
		p = ep->CELL.task_kill.source;
		size = sizeof(ep->CELL.task_kill.source);
		retn = crypto_shash_finup(shash, p, size, mapping);
		break;

	case TSEM_TASK_SETPGID:
		p = ep->CELL.task_kill.target;
		size = sizeof(ep->CELL.task_kill.target);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = ep->CELL.task_kill.source;
		size = sizeof(ep->CELL.task_kill.source);
		retn = crypto_shash_finup(shash, p, size, mapping);
		break;

	case TSEM_TASK_GETPGID:
	case TSEM_TASK_GETSID:
	case TSEM_TASK_GETIOPRIO:
	case TSEM_TASK_SETSCHEDULER:
	case TSEM_TASK_GETSCHEDULER:
		p = ep->CELL.task_kill.target;
		size = sizeof(ep->CELL.task_kill.target);
		retn = crypto_shash_finup(shash, p, size, mapping);
		break;

	case TSEM_TASK_SETNICE:
	case TSEM_TASK_SETIOPRIO:
		p = ep->CELL.task_kill.target;
		size = sizeof(ep->CELL.task_kill.target);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.task_kill.u.value);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_TASK_PRLIMIT:
		retn = add_creds(shash, &ep->CELL.task_prlimit.out.cred);
		if (retn)
			goto done;

		retn = add_creds(shash, &ep->CELL.task_prlimit.out.tcred);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.task_prlimit.flags);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_TASK_SETRLIMIT:
		p = ep->CELL.task_kill.target;
		size = sizeof(ep->CELL.task_kill.target);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.task_kill.u.resource);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_kill.cur);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_kill.max);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_TASK_PRCTL:
		retn = add_u32(shash, ep->CELL.task_prctl.option);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_prctl.arg2);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_prctl.arg3);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_prctl.arg4);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.task_prctl.arg5);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;


	case TSEM_INODE_GETATTR:
		retn = add_path(shash, &ep->CELL.inode_attr.out.path);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode_attr.out.inode);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_SETATTR:
		retn = add_path(shash, &ep->CELL.inode_attr.out.path);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode_attr.out.inode);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode_attr.out.valid);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode_attr.out.mode);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode_attr.out.uid);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode_attr.out.gid);
		if (retn)
			goto done;

		retn = add_u64(shash, ep->CELL.inode_attr.out.size);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_SETXATTR:
		retn = add_path(shash, &ep->CELL.inode_xattr.out.path);
		if (retn)
			goto done;

		retn = add_str(shash, ep->CELL.inode_xattr.out.name);
		if (retn)
			goto done;

		retn = crypto_shash_update(shash,
					   ep->CELL.inode_xattr.out.value,
					   ep->CELL.inode_xattr.out.size);
		if (retn)
			goto done;

		retn = add_u32(shash, ep->CELL.inode_xattr.out.flags);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_INODE_GETXATTR:
		retn = add_path(shash, &ep->CELL.inode_xattr.out.path);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.inode_xattr.out.inode);
		if (retn)
			goto done;

		retn = add_str(shash, ep->CELL.inode_xattr.out.name);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SB_PIVOTROOT:
		retn = add_path(shash, &ep->CELL.sb_pivotroot.out.old_path);
		if (retn)
			goto done;

		retn = add_path(shash, &ep->CELL.sb_pivotroot.out.new_path);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	case TSEM_SB_STATFS:
	case TSEM_INODE_LISTXATTR:
		retn = add_path(shash, &ep->CELL.sb.out.path);
		if (retn)
			goto done;

		retn = add_inode(shash, &ep->CELL.sb.out.inode);
		if (retn)
			goto done;

		retn = crypto_shash_final(shash, mapping);
		break;

	default:
		p = (u8 *) tsem_names[ep->event];
		size = strlen(tsem_names[ep->event]);
		retn = crypto_shash_update(shash, p, size);
		if (retn)
			goto done;

		p = tsem_context(current)->zero_digest;
		size = tsem_digestsize();
		retn = crypto_shash_finup(shash, p, size, mapping);
		if (retn)
			goto done;
		break;
	}

 done:
	if (ep->event == TSEM_INODE_SETXATTR) {
		kfree(ep->CELL.inode_xattr.out.value);
		ep->CELL.inode_xattr.out.value = NULL;
	}

	return retn;
}

static int get_event_mapping(int event, u8 *p_task_id, u8 *task_id,
			     u8 *COE_id, u8 *cell_id, u8 *mapping)
{
	int retn = 0;
	u32 event_id = (u32) event;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, tsem_names[event_id],
				   strlen(tsem_names[event_id]));
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, p_task_id, tsem_digestsize());
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, task_id, tsem_digestsize());
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, COE_id, tsem_digestsize());
	if (retn)
		goto done;

	retn = crypto_shash_finup(shash, cell_id, tsem_digestsize(), mapping);

 done:
	return retn;
}

static int map_event(struct tsem_event *ep, u8 *p_task_id, u8 *task_id,
		     u8 *event_mapping)
{
	int retn;
	u8 COE_mapping[HASH_MAX_DIGESTSIZE];
	u8 cell_mapping[HASH_MAX_DIGESTSIZE];

	retn = get_COE_mapping(ep, COE_mapping);
	if (retn)
		goto done;

	retn = get_cell_mapping(ep, cell_mapping);
	if (retn)
		goto done;

	retn = get_event_mapping(ep->event, p_task_id, task_id, COE_mapping,
				 cell_mapping, event_mapping);
 done:
	return retn;
}

/**
 * tsem_map_task() - Create the task identity description structure.
 * @file: A pointer to the file structure defining the executable.
 * @task_id: Pointer to the buffer that the task id will be copied to.
 *
 * This function creates the security event state point that will be used
 * as the task identifier for the generation of security state points
 * that are created by the process that task identifier is assigned to.
 *
 * Return: This function returns 0 if the mapping was successfully
 *	   created and an error value otherwise.
 */
int tsem_map_task(struct file *file, u8 *task_id)
{
	int retn;
	u8 null_taskid[HASH_MAX_DIGESTSIZE];
	struct tsem_event *ep;

	ep = tsem_event_allocate(TSEM_BPRM_COMMITTING_CREDS, false);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;
	retn = tsem_event_init(ep);
	if (retn)
		return retn;

	memset(null_taskid, '\0', tsem_digestsize());
	retn = map_event(ep, tsem_task(current)->p_task_id, null_taskid,
			 task_id);
	tsem_event_put(ep);

	return 0;
}

/**
 * tsem_map_event() - Create a security event mapping.
 * @event: The number of the event to be mapped.
 * @params: A pointer to the structure containing the event description
 *	    parameters.
 *
 * This function creates a structure to describe a security event
 * and maps the event into a security state coefficient.
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int tsem_map_event(struct tsem_event *ep)
{
	struct tsem_task *task = tsem_task(current);

	return map_event(ep, task->p_task_id, task->task_id, ep->mapping);
}
