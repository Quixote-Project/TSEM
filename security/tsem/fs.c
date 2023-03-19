// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements the securityfs based control plane.
 */

#include <linux/seq_file.h>
#include <linux/poll.h>

#include "tsem.h"

static struct dentry *control;
static struct dentry *tsem_dir;
static struct dentry *points;
static struct dentry *forensics;
static struct dentry *measurement_file;
static struct dentry *trajectory;
static struct dentry *state;
static struct dentry *id;
static struct dentry *aggregate;
static struct dentry *external_tma;

struct control_commands {
	char *cmd;
	enum tsem_control_type type;
};

static struct control_commands commands[] = {
	{"internal", TSEM_CONTROL_INTERNAL},
	{"external", TSEM_CONTROL_EXTERNAL},
	{"enforce", TSEM_CONTROL_ENFORCE},
	{"seal", TSEM_CONTROL_SEAL},
	{"trusted", TSEM_CONTROL_TRUSTED},
	{"untrusted", TSEM_CONTROL_UNTRUSTED},
	{"state", TSEM_CONTROL_MAP_STATE},
	{"pseudonym", TSEM_CONTROL_MAP_PSEUDONYM},
	{"base ", TSEM_CONTROL_MAP_BASE}
};

static bool can_access_fs(void)
{
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (ctx->external)
		return false;
	if (capable(TSEM_CONTROL_CAPABILITY))
		return true;
	if (ctx->sealed)
		return false;
	return true;
}

static int control_COE(unsigned long cmd, pid_t pid, char *keystr)
{
	bool wakeup = false;
	int retn = -ESRCH;
	u8 event_key[WP256_DIGEST_SIZE];
	struct task_struct *COE;
	struct tsem_task *task;
	struct tsem_task *tma = tsem_task(current);
	struct crypto_shash *tfm = NULL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rcu_read_lock();
	COE = find_task_by_vpid(pid);
	if (COE != NULL) {
		task = tsem_task(COE);
		retn = tsem_ns_event_key(tfm, task->task_key, keystr,
					 event_key);
		if (retn)
			goto done;

		if (memcmp(tma->task_key, event_key, sizeof(tma->task_key))) {
			pr_warn("tsem: Invalid process release request.\n");
			retn = -EINVAL;
			goto done;
		}

		if (cmd == TSEM_CONTROL_UNTRUSTED)
			task->trust_status = TSEM_TASK_UNTRUSTED;
		if (cmd == TSEM_CONTROL_TRUSTED) {
			task->trust_status &= ~TSEM_TASK_TRUST_PENDING;
			if (tsem_task_trusted(COE))
				task->trust_status = TSEM_TASK_TRUSTED;
		}
		retn = 0;
		wakeup = true;
	}

 done:
	rcu_read_unlock();

	if (wakeup)
		wake_up_process(COE);

	crypto_free_shash(tfm);
	return retn;
}

static int config_context(unsigned long cmd, char *bufr)
{
	int retn = -EINVAL;
	unsigned int lp;
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (ctx->sealed)
		return -EPERM;

	if (cmd == TSEM_CONTROL_SEAL) {
		ctx->sealed = true;
		retn = 0;
	}

	if (cmd == TSEM_CONTROL_ENFORCE) {
		for (lp = 0; lp < ARRAY_SIZE(tsem_root_actions); ++lp)
			ctx->actions[lp] = TSEM_ACTION_EPERM;
		retn = 0;
	}

	return retn;
}

static int config_point(enum tsem_control_type type, u8 *arg)
{
	int retn = -EINVAL;
	u8 mapping[WP256_DIGEST_SIZE];

	if (strlen(arg) != sizeof(mapping) * 2)
		goto done;
	if (hex2bin(mapping, arg, sizeof(mapping)))
		goto done;

	if (type == TSEM_CONTROL_MAP_STATE)
		retn = tsem_model_load_point(mapping);
	else if (type == TSEM_CONTROL_MAP_PSEUDONYM)
		retn = tsem_model_load_pseudonym(mapping);
	else {
		tsem_model_load_base(mapping);
		retn = 0;
	}

 done:
	return retn;
}

static void show_event(struct seq_file *c, struct tsem_event *ep, char *file)
{
	tsem_fs_show_field(c, "event");
	if (ep->pid)
		tsem_fs_show_key(c, ",", "pid", "%u", ep->pid);
	tsem_fs_show_key(c, ",", "process", "%s", ep->comm);
	tsem_fs_show_key(c, ",", "filename", "%s", file ? file : "none");
	tsem_fs_show_key(c, ",", "type", "%s", tsem_names[ep->event]);
	tsem_fs_show_key(c, "}, ", "task_id", "%*phN",
			 WP256_DIGEST_SIZE, ep->task_id);

	tsem_fs_show_field(c, "COE");
	tsem_fs_show_key(c, ",", "uid", "%d", ep->COE.uid);
	tsem_fs_show_key(c, ",", "euid", "%d", ep->COE.euid);
	tsem_fs_show_key(c, ",", "suid", "%d", ep->COE.suid);
	tsem_fs_show_key(c, ",", "gid", "%d", ep->COE.gid);
	tsem_fs_show_key(c, ",", "egid", "%d", ep->COE.egid);
	tsem_fs_show_key(c, ",", "sgid", "%d", ep->COE.sgid);
	tsem_fs_show_key(c, ",", "fsuid", "%d", ep->COE.fsuid);
	tsem_fs_show_key(c, ",", "fsgid", "%d", ep->COE.fsgid);
	tsem_fs_show_key(c, "}, ", "cap", "0x%llx", ep->COE.capability.value);
}

static void show_file(struct seq_file *c, struct tsem_event *ep)
{
	if (ep->event == TSEM_FILE_OPEN)
		tsem_fs_show_field(c, "file_open");
	else
		tsem_fs_show_field(c, "file");

	tsem_fs_show_key(c, ",", "flags", "%u", ep->file.flags);
	tsem_fs_show_key(c, ",", "uid", "%d", ep->file.uid);
	tsem_fs_show_key(c, ",", "gid", "%d", ep->file.gid);
	tsem_fs_show_key(c, ",", "mode", "0%o", ep->file.mode);
	tsem_fs_show_key(c, ",", "name_length", "%u", ep->file.name_length);
	tsem_fs_show_key(c, ",", "name", "%*phN", WP256_DIGEST_SIZE,
			 ep->file.name);
	tsem_fs_show_key(c, ",", "s_magic", "0x%0x", ep->file.s_magic);
	tsem_fs_show_key(c, ",", "s_id", "%s", ep->file.s_id);
	tsem_fs_show_key(c, ",", "s_uuid", "%*phN", sizeof(ep->file.s_uuid),
		 ep->file.s_uuid);
	tsem_fs_show_key(c, "}", "digest", "%*phN", WP256_DIGEST_SIZE,
		 ep->file.digest);
}

static void show_mmap(struct seq_file *c, struct tsem_event *ep)
{
	struct tsem_mmap_file_args *args = &ep->CELL.mmap_file;

	show_event(c, ep, args->file ? ep->pathname : NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, ",", "type", "%u", args->file == NULL);
	tsem_fs_show_key(c, ",", "reqprot", "%u", args->reqprot);
	tsem_fs_show_key(c, ",", "prot", "%u", args->prot);

	if (args->file) {
		tsem_fs_show_key(c, ",", "flags", "%u", args->flags);
		show_file(c, ep);
		seq_putc(c, '}');
	}
	else
		tsem_fs_show_key(c, "}", "flags", "%u", args->flags);
}

static void show_socket_create(struct seq_file *c, struct tsem_event *ep)
{
	struct tsem_socket_create_args *args = &ep->CELL.socket_create;

	show_event(c, ep, NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, ",", "family", "%u", args->family);
	tsem_fs_show_key(c, ",", "type", "%u", args->type);
	tsem_fs_show_key(c, ",", "protocol", "%u", args->protocol);
	tsem_fs_show_key(c, "}", "kern", "%u", args->kern);
}

static void show_socket(struct seq_file *c, struct tsem_event *ep)
{
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	struct tsem_socket_connect_args *scp = &ep->CELL.socket_connect;

	show_event(c, ep, NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, ",", "family", "%u", scp->family);

	switch (scp->family) {
	case AF_INET:
		ipv4 = (struct sockaddr_in *) &scp->u.ipv4;
		tsem_fs_show_key(c, ",", "port", "%u", ipv4->sin_port);
		tsem_fs_show_key(c, "}", "addr", "%u", ipv4->sin_addr.s_addr);
		break;
	case AF_INET6:
		ipv6 = (struct sockaddr_in6 *) &scp->u.ipv6;
		tsem_fs_show_key(c, ",", "port", "%u", ipv6->sin6_port);
		tsem_fs_show_key(c, ",", "flow", "%u", ipv6->sin6_flowinfo);
		tsem_fs_show_key(c, ",", "scope", "%u", ipv6->sin6_scope_id);
		tsem_fs_show_key(c, "}", "addr", "%*phN",
			 (int) sizeof(ipv6->sin6_addr.in6_u.u6_addr8),
			 ipv6->sin6_addr.in6_u.u6_addr8);
		break;
	default:
		tsem_fs_show_key(c, "}", "addr", "%*phN", WP256_DIGEST_SIZE,
				 scp->u.mapping);
		break;
	}
}

static void show_socket_accept(struct seq_file *c, struct tsem_event *ep)
{
	struct tsem_socket_accept_args *sap = &ep->CELL.socket_accept;

	show_event(c, ep, NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, ",", "family", "%u", sap->family);
	tsem_fs_show_key(c, ",", "type", "%u", sap->type);
	tsem_fs_show_key(c, ",", "port", "%u", sap->port);

	switch (sap->family) {
	case AF_INET:
		tsem_fs_show_key(c, "}", "addr", "%u", sap->ipv4);
		break;
	case AF_INET6:
		tsem_fs_show_key(c, "}", "addr", "%*phN",
			 (int) sizeof(sap->ipv6.in6_u.u6_addr8),
			 sap->ipv6.in6_u.u6_addr8);
		break;
	default:
		tsem_fs_show_key(c, "}", "addr", "%*phN",
			 (int) sizeof(sap->tsip->digest), sap->tsip->digest);
		break;
	}
}

static void show_task_kill(struct seq_file *c, struct tsem_event *ep)
{
	struct tsem_task_kill_args *args = &ep->CELL.task_kill;

	show_event(c, ep, NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, ",", "cross", "%u", args->cross_model);
	tsem_fs_show_key(c, ",", "signal", "%u", args->signal);
	tsem_fs_show_key(c, "}", "target", "*%phN",
			 WP256_DIGEST_SIZE, args->target);
}

static void show_event_generic(struct seq_file *c, struct tsem_event *ep)
{
	show_event(c, ep, NULL);

	tsem_fs_show_field(c, tsem_names[ep->event]);
	tsem_fs_show_key(c, "}", "type", "%s",
			 tsem_names[ep->CELL.event_type]);
}

static void *trajectory_start(struct seq_file *c, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_lock(&model->trajectory_mutex);
	return seq_list_start(&model->trajectory_list, *pos);
}

static void *trajectory_next(struct seq_file *c, void *p, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	return seq_list_next(p, &model->trajectory_list, pos);
}

static void trajectory_stop(struct seq_file *c, void *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_unlock(&model->trajectory_mutex);
}

static int trajectory_show(struct seq_file *c, void *trajectory)
{
	struct tsem_trajectory *pt;
	struct tsem_event *ep;

	pt = list_entry(trajectory, struct tsem_trajectory, list);
	ep = pt->ep;

	seq_putc(c, '{');
	tsem_fs_show_trajectory(c, ep);
	seq_puts(c, "}\n");

	return 0;
}

static const struct seq_operations trajectory_seqops = {
	.start = trajectory_start,
	.next = trajectory_next,
	.stop = trajectory_stop,
	.show = trajectory_show
};

static int trajectory_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return seq_open(file, &trajectory_seqops);
}

static const struct file_operations trajectory_ops = {
	.open = trajectory_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static void *point_start(struct seq_file *c, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_lock(&model->point_mutex);
	return seq_list_start(&model->point_list, *pos);
}

static void *point_next(struct seq_file *c, void *p, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	return seq_list_next(p, &model->point_list, pos);
}

static void point_stop(struct seq_file *c, void *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_unlock(&model->point_mutex);
}

static int point_show(struct seq_file *c, void *point)
{
	struct tsem_event_point *id;

	id = list_entry(point, struct tsem_event_point, list);
	seq_printf(c, "%*phN\n", WP256_DIGEST_SIZE, id->point);
	return 0;
}

static const struct seq_operations point_seqops = {
	.start = point_start,
	.next = point_next,
	.stop = point_stop,
	.show = point_show
};

static int point_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return seq_open(file, &point_seqops);
}

static const struct file_operations point_ops = {
	.open = point_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int open_control(struct inode *inode, struct file *filp)
{
	if (!capable(TSEM_CONTROL_CAPABILITY))
		return -EACCES;
	if (!(filp->f_flags & O_WRONLY))
		return -EACCES;
	return 0;
}

static ssize_t write_control(struct file *file, const char __user *buf,
			     size_t datalen, loff_t *ppos)
{
	char *p, *key, *arg, cmdbufr[128];
	unsigned int lp;
	ssize_t retn = -EINVAL;
	long pid;
	enum tsem_control_type type;

	if (*ppos != 0)
		goto done;
	if (datalen > sizeof(cmdbufr)-1)
		goto done;

	memset(cmdbufr, '\0', sizeof(cmdbufr));
	if (copy_from_user(cmdbufr, buf, datalen)) {
		retn = -EFAULT;
		goto done;
	}

	p = strchr(cmdbufr, '\n');
	if (!p)
		goto done;
	*p = '\0';

	arg = strchr(cmdbufr, ' ');
	if (arg != NULL) {
		*arg = '\0';
		++arg;
	}

	for (lp = 0; lp < ARRAY_SIZE(commands); ++lp) {
		if (!strncmp(cmdbufr, commands[lp].cmd,
			     strlen(commands[lp].cmd))) {
			type = commands[lp].type;
			break;
		}
	}

	switch (type) {
	case TSEM_CONTROL_EXTERNAL:
		if (!arg)
			goto done;
		retn = tsem_ns_create(type, arg);
		break;
	case TSEM_CONTROL_INTERNAL:
		retn = tsem_ns_create(type, NULL);
		break;
	case TSEM_CONTROL_ENFORCE:
	case TSEM_CONTROL_SEAL:
		retn = config_context(type, cmdbufr);
		break;
	case TSEM_CONTROL_TRUSTED:
	case TSEM_CONTROL_UNTRUSTED:
		if (!arg)
			goto done;

		key = strchr(arg, ' ');
		if (!key)
			goto done;
		*key++ = '\0';
		if (strlen(key) != WP256_DIGEST_SIZE * 2)
			goto done;

		if (kstrtol(arg, 0, &pid))
			goto done;
		retn = control_COE(type, pid, key);
		break;
	case TSEM_CONTROL_MAP_STATE:
	case TSEM_CONTROL_MAP_PSEUDONYM:
	case TSEM_CONTROL_MAP_BASE:
		if (!arg)
			goto done;
		retn = config_point(type, arg);
		break;
	}

done:
	if (!retn)
		retn = datalen;
	return retn;
}

static int release_control(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations control_ops = {
	.open = open_control,
	.write = write_control,
	.release = release_control,
	.llseek = generic_file_llseek,
};

static void *forensics_start(struct seq_file *c, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_lock(&model->forensics_mutex);
	return seq_list_start(&model->forensics_list, *pos);
}

static void *forensics_next(struct seq_file *c, void *p, loff_t *pos)
{
	struct tsem_model *model = tsem_model(current);

	return seq_list_next(p, &model->forensics_list, pos);
}

static void forensics_stop(struct seq_file *c, void *pos)
{
	struct tsem_model *model = tsem_model(current);

	mutex_unlock(&model->forensics_mutex);
}

static int forensics_show(struct seq_file *c, void *event)
{
	struct tsem_trajectory *pt;
	struct tsem_event *ep;

	pt = list_entry(event, struct tsem_trajectory, list);
	ep = pt->ep;

	seq_putc(c, '{');
	tsem_fs_show_trajectory(c, ep);
	seq_puts(c, "}\n");

	return 0;
}

static const struct seq_operations forensics_seqops = {
	.start = forensics_start,
	.next = forensics_next,
	.stop = forensics_stop,
	.show = forensics_show
};

static int forensics_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return seq_open(file, &forensics_seqops);
}

static const struct file_operations forensics_ops = {
	.open = forensics_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int measurement_show(struct seq_file *c, void *event)
{
	struct tsem_model *model = tsem_model(current);

	seq_printf(c, "%*phN\n", (int) sizeof(model->measurement),
		   model->measurement);
	return 0;
}

static int measurement_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return single_open(file, &measurement_show, NULL);
}

static const struct file_operations measurement_ops = {
	.open = measurement_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int id_show(struct seq_file *c, void *event)
{
	seq_printf(c, "%llu\n", tsem_context(current)->id);
	return 0;
}

static int id_open(struct inode *inode, struct file *file)
{
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (ctx->sealed)
		return -EACCES;
	return single_open(file, &id_show, NULL);
}

static const struct file_operations id_ops = {
	.open = id_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int state_show(struct seq_file *m, void *v)
{
	struct tsem_model *model = tsem_model(current);

	tsem_model_compute_state();
	seq_printf(m, "%*phN\n", WP256_DIGEST_SIZE, model->state);
	return 0;
}

static int state_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return single_open(file, &state_show, NULL);
}

static const struct file_operations state_ops = {
	.open = state_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int aggregate_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%*phN\n", WP256_DIGEST_SIZE, tsem_trust_aggregate());
	return 0;
}

static int aggregate_open(struct inode *inode, struct file *file)
{
	if (!can_access_fs())
		return -EACCES;
	return single_open(file, &aggregate_show, NULL);
}

static const struct file_operations aggregate_ops = {
	.open = aggregate_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static __poll_t export_poll(struct file *file, struct poll_table_struct *wait)
{
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (!ctx->external)
		return -ENOENT;

	poll_wait(file, &ctx->external->wq, wait);

	if (ctx->external->have_event) {
		ctx->external->have_event = false;
		return EPOLLIN | EPOLLRDNORM;
	}
	return 0;
}

static int export_open(struct inode *inode, struct file *file)
{
	if (!capable(TSEM_CONTROL_CAPABILITY))
		return -EACCES;
	return single_open(file, &tsem_export_show, NULL);
}

static const struct file_operations export_ops = {
	.open = export_open,
	.poll = export_poll,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/**
 * tsem_fs_create_external() - Create an external TMA update file.
 * @id: A pointer to the ASCII representation of the modeling domain
 *      that the export file is being created for.
 *
 * This function is used to create a pseudo-file that will output security
 * event descriptions for a namespace.  This routine will create the
 * following file:
 *
 * /sys/kernel/security/tsem/ExternalTMA/N
 *
 * Where N is replaced with the security model context identifier.
 *
 * Return: If creation of the update file is successful a pointer to the
 *	   dentry of the file is returned.  If an error was encountered
 *	   the pointer with an encoded code will be returned.
 */
struct dentry *tsem_fs_create_external(const char *name)
{

	return securityfs_create_file(name, 0400, external_tma, NULL,
				      &export_ops);
}

/**
 * tsem_fs_show_export() - Generate the output of a security event.
 * @sf: A pointer to the seq_file structure to which output will
 *      be set.
 * @ep: A pointer to the event description that is to be output.
 *
 * This function is used to generate a record that will be output to
 * the pseudo-file that outputs the security events for the
 * domain being modeled.
 */
void tsem_fs_show_trajectory(struct seq_file *c, struct tsem_event *ep)
{
	switch (ep->event) {
	case TSEM_FILE_OPEN:
		show_event(c, ep, ep->pathname);
		show_file(c, ep);
		break;
	case TSEM_MMAP_FILE:
		show_mmap(c, ep);
		break;
	case TSEM_SOCKET_CREATE:
		show_socket_create(c, ep);
		break;
	case TSEM_SOCKET_CONNECT:
	case TSEM_SOCKET_BIND:
		show_socket(c, ep);
		break;
	case TSEM_SOCKET_ACCEPT:
		show_socket_accept(c, ep);
		break;
	case TSEM_TASK_KILL:
		show_task_kill(c, ep);
		break;
	case TSEM_GENERIC_EVENT:
		show_event_generic(c, ep);
		break;
	default:
		break;
	}
}

/**
 * tesm_fs_show_field() - Output a JSON field description
 * @sf: A pointer to the seq_file structure that the field description
 *	is to be written to.
 * @f:  A pointer to null terminated character buffer containing the
 *      name of the field to encode
 *
 * This function is used to generate a JSON field description that
 * is used to name a sequence of key/value pairs describing the
 * characteristcis of the field.
 */
void tsem_fs_show_field(struct seq_file *c, const char *field)
{
	seq_printf(c, "\"%s\": {", field);
}

/**
 * tesm_fs_tsem_fs_show_key() - Output a JSON key/value pair
 * @sf: A pointer to the seq_file structure that the field description
 *	is to be written to.
 * @term: A pointer to a null-terminated character buffer containing
 *	  the string that is to be used for terminating the key/value
 *	  pair.
 * @key: A pointer to the null-terminated character buffer containing
 *	 the key description.
 * @fmt: The printf format that is to be used for formatting the
 *	 value of the key.
 *
 * This function is a variadic function that is used to encode a
 * JSON key/value pair that provides one of characteristics of an
 * event description field.
 */
void tsem_fs_show_key(struct seq_file *c, char *term, char *key,
		      char *fmt, ...)
{
	va_list args;

	seq_printf(c, "\"%s\": \"", key);

	va_start(args, fmt);
	seq_vprintf(c, fmt, args);
	va_end(args);

	if (term[0] == ',')
		seq_printf(c, "\"%s ", term);
	else
		seq_printf(c, "\"%s", term);
}

/**
 * tesm_fs_init() - Initialize the TSEM control filesystem heirarchy
 *
 * This function is called as part of the TSEM LSM initialization
 * process.  The purpose of this function is to create the TSEM
 * control plane, based on the securityfs filesystem, by creating the
 * /sys/kernel/security/tsem directory and populating that directory
 * with the control plane files and internal TMA model information
 * files.  The /sys/kernel/security/tsem/ExternalTMA directory is
 * also created.  This directory will be used to hold the modeling
 * domain specific files that will emit the security event descriptions
 * for the domain.
 *
 * Return: If filesystem initialization is successful a return code of 0
 *	   is returned.  A negative return value is returned if an error
 *	   is encountered.
 */
int __init tsem_fs_init(void)
{
	int retn = -1;

	tsem_dir = securityfs_create_dir("tsem", NULL);
	if (tsem_dir == NULL)
		goto done;

	control = securityfs_create_file("control", 0200, tsem_dir, NULL,
					 &control_ops);
	if (IS_ERR(control))
		goto err;

	points = securityfs_create_file("points", 0400, tsem_dir, NULL,
					&point_ops);
	if (IS_ERR(points))
		goto err;

	forensics = securityfs_create_file("forensics", 0400, tsem_dir, NULL,
					   &forensics_ops);
	if (IS_ERR(forensics))
		goto err;

	measurement_file = securityfs_create_file("measurement", 0400,
						  tsem_dir, NULL,
						  &measurement_ops);
	if (IS_ERR(measurement_file))
		goto err;

	trajectory = securityfs_create_file("trajectory", 0400, tsem_dir, NULL,
					    &trajectory_ops);
	if (IS_ERR(trajectory))
		goto err;

	state = securityfs_create_file("state", 0400, tsem_dir, NULL,
				       &state_ops);
	if (IS_ERR(state))
		goto err;

	id = securityfs_create_file("id", 0400, tsem_dir, NULL, &id_ops);
	if (IS_ERR(control))
		goto err;

	aggregate = securityfs_create_file("aggregate", 0400, tsem_dir, NULL,
					   &aggregate_ops);
	if (IS_ERR(aggregate))
		goto err;

	external_tma = securityfs_create_dir("ExternalTMA", tsem_dir);
	if (IS_ERR(external_tma))
		goto err;

	retn = 0;

 done:
	return retn;

 err:
	securityfs_remove(control);
	securityfs_remove(points);
	securityfs_remove(forensics);
	securityfs_remove(measurement_file);
	securityfs_remove(trajectory);
	securityfs_remove(state);
	securityfs_remove(id);
	securityfs_remove(aggregate);
	securityfs_remove(external_tma);

	return retn;

}
