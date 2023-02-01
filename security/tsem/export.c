// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements updates to an external modeling engine.
 */

#include <linux/seq_file.h>

#include "tsem.h"

enum export_events_type {
	AGGREGATE_EVENT = 1,
	EXPORT_EVENT,
	LOG_EVENT
};

struct action_description {
	enum tsem_event_type type;
	enum tsem_action_type action;
	char comm[TASK_COMM_LEN];
};

struct export_event {
	struct list_head list;
	enum export_events_type type;
	union {
		u8 *aggregate[WP256_DIGEST_SIZE];
		struct tsem_event *ep;
		struct action_description action;
	} u;
};

static const char * const tsem_actions[TSEM_ACTION_CNT] = {
	"LOG",
	"DENY"
};

static void trigger_event(struct tsem_TMA_context *ctx)
{
	ctx->external->have_event = true;
	wake_up_interruptible(&ctx->external->wq);
}

static void show_event_coe(struct tsem_event *ep, struct seq_file *page)
{
	seq_printf(page, "export pid{%u} ", ep->pid);

	seq_printf(page, "event{process=%s, filename=%s, ", ep->comm,
			   ep->pathname == NULL ? "none" : ep->pathname);
	seq_printf(page, "type=%s, task_id=%*phN} ", tsem_names[ep->event],
		   WP256_DIGEST_SIZE, ep->task_id);

	seq_printf(page, "COE{uid=%d, euid=%d, suid=%d, gid=%d, ", ep->COE.uid,
		   ep->COE.euid, ep->COE.suid, ep->COE.gid);
	seq_printf(page, "egid=%d, sgid=%d, fsuid=%d, fsgid=%d, ",
		   ep->COE.egid, ep->COE.sgid, ep->COE.fsuid, ep->COE.fsgid);
	seq_printf(page, "cap=0x%llx} ", ep->COE.capability.value);
}

static void show_file(struct tsem_event *ep, struct seq_file *page)
{
	seq_printf(page, "file{flags=%u, uid=%d, gid=%d, mode=0%o, ",
		ep->file.flags, ep->file.uid, ep->file.gid, ep->file.mode);
	seq_printf(page, "name_length=%u, name=%*phN, s_magic=0x%0x, ",
		   ep->file.name_length, WP256_DIGEST_SIZE, ep->file.name,
		   ep->file.s_magic);
	seq_printf(page, "s_id=%s, s_uuid=%*phN, digest=%*phN}\n",
		   ep->file.s_id, (int) sizeof(ep->file.s_uuid),
		   ep->file.s_uuid, WP256_DIGEST_SIZE, ep->file.digest);
}

static void show_mmap_file(struct tsem_event *ep, struct seq_file *page)
{
	show_event_coe(ep, page);

	seq_printf(page, "%s{type=%u, reqprot=%u, ", tsem_names[ep->event],
		   ep->CELL.mmap_file.anonymous, ep->CELL.mmap_file.reqprot);
	seq_printf(page, "prot=%u, flags=%u}", ep->CELL.mmap_file.prot,
		   ep->CELL.mmap_file.flags);

	if (!ep->CELL.mmap_file.anonymous) {
		seq_puts(page, " ");
		show_file(ep, page);
	} else
		seq_puts(page, "\n");
}

static void show_ipv4_socket(struct tsem_event *ep, struct seq_file *page)
{
	struct sockaddr_in *ipv4 = &ep->CELL.socket_connect.u.ipv4;

	show_event_coe(ep, page);
	seq_printf(page, "%s{family=%u, port=%u, addr=%u}\n",
		   tsem_names[ep->event], ipv4->sin_family, ipv4->sin_port,
		   ipv4->sin_addr.s_addr);
}

static void show_ipv6_socket(struct tsem_event *ep, struct seq_file *page)
{
	struct sockaddr_in6 *ipv6 = &ep->CELL.socket_connect.u.ipv6;

	show_event_coe(ep, page);

	seq_printf(page, "%s{family=%u, port=%u, flow=%u, ",
		   tsem_names[ep->event], ipv6->sin6_family,
		   ipv6->sin6_port, ipv6->sin6_flowinfo);
	seq_printf(page, "scope=%u, addr=%*phN}\n", ipv6->sin6_scope_id,
		       (int) sizeof(ipv6->sin6_addr.in6_u.u6_addr8),
		       ipv6->sin6_addr.in6_u.u6_addr8);
}

static void show_socket(struct tsem_event *ep, struct seq_file *page)
{
	struct tsem_socket_connect_args *scp = &ep->CELL.socket_connect;

	show_event_coe(ep, page);

	seq_printf(page, "%s{family=%u, addr=%*phN}\n", tsem_names[ep->event],
		   scp->family, WP256_DIGEST_SIZE, scp->u.mapping);
}

static void show_socket_create(struct tsem_event *ep, struct seq_file *page)
{
	show_event_coe(ep, page);

	seq_printf(page, "%s{family=%u, type=%u, ", tsem_names[ep->event],
		   ep->CELL.socket_create.family, ep->CELL.socket_create.type);
	seq_printf(page, "protocol=%u, kern=%u}\n",
		   ep->CELL.socket_create.protocol,
		   ep->CELL.socket_create.kern);
}

static void show_socket_accept(struct tsem_event *ep, struct seq_file *page)
{
	u8 *p;
	int size;
	struct tsem_socket_accept_args *sap = &ep->CELL.socket_accept;

	show_event_coe(ep, page);

	seq_printf(page, "%s{family=%u, type=%u, port=%u, addr=",
		   tsem_names[ep->event], sap->family, sap->type, sap->port);

	if (sap->family == AF_INET) {
		seq_printf(page, "%u}\n", sap->ipv4);
		return;
	}

	if (sap->family == AF_INET6) {
		p = sap->ipv6.in6_u.u6_addr8;
		size = sizeof(sap->ipv6.in6_u.u6_addr8);
	} else {
		p = sap->tsip->digest;
		size = sizeof(sap->tsip->digest);
	}
	seq_printf(page, "%*phN}\n", size, p);
}

static void show_socket_events(struct tsem_event *ep, struct seq_file *page)
{
	switch (ep->event) {
	case TSEM_SOCKET_CREATE:
		show_socket_create(ep, page);
		break;

	case TSEM_SOCKET_CONNECT:
	case TSEM_SOCKET_BIND:
		switch (ep->CELL.socket_connect.family) {
		case AF_INET:
			show_ipv4_socket(ep, page);
			break;
		case AF_INET6:
			show_ipv6_socket(ep, page);
			break;
		default:
			show_socket(ep, page);
			break;
		}
		break;

	case TSEM_SOCKET_ACCEPT:
		show_socket_accept(ep, page);
		break;

	default:
		break;
	}
}

static void show_task_kill(struct tsem_event *ep, struct seq_file *page)
{
	struct tsem_task_kill_args *args = &ep->CELL.task_kill;

	show_event_coe(ep, page);

	seq_printf(page, "%s{cross=%u, signal=%u, target=%*phN}\n",
		   tsem_names[ep->event], args->cross_model,
		   args->signal, WP256_DIGEST_SIZE, args->target);
}

static void show_event_generic(struct tsem_event *ep, struct seq_file *page)
{
	show_event_coe(ep, page);

	seq_printf(page, "%s{type=%s}\n", tsem_names[ep->event],
		   tsem_names[ep->CELL.event_type]);
}

int tsem_export_show(struct seq_file *page)
{
	ssize_t retn = -ENODATA;
	struct export_event *mp;
	struct tsem_event *ep;
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (!ctx->id)
		return -EPERM;

	mutex_lock(&ctx->external->measurement_mutex);
	if (list_empty(&ctx->external->measurement_list))
		goto done;
	mp = list_first_entry(&ctx->external->measurement_list,
			      struct export_event, list);

	switch (mp->type) {
	case AGGREGATE_EVENT:
		seq_printf(page, "aggregate %*phN\n", WP256_DIGEST_SIZE,
			   mp->u.aggregate);
		break;

	case EXPORT_EVENT:
		ep = mp->u.ep;
		switch (ep->event) {
		case TSEM_FILE_OPEN:
			show_event_coe(ep, page);
			show_file(ep, page);
			break;

		case TSEM_MMAP_FILE:
			show_mmap_file(ep, page);
			break;

		case TSEM_SOCKET_CREATE:
		case TSEM_SOCKET_CONNECT:
		case TSEM_SOCKET_BIND:
		case TSEM_SOCKET_ACCEPT:
			show_socket_events(ep, page);
			break;

		case TSEM_TASK_KILL:
			show_task_kill(ep, page);
			break;

		case TSEM_GENERIC_EVENT:
			show_event_generic(ep, page);
			break;

		default:
			break;
		}
		tsem_event_put(ep);
		break;

	case LOG_EVENT:
		seq_printf(page, "log process{%s} event{%s} action{%s}\n",
			    mp->u.action.comm, tsem_names[mp->u.action.type],
			    tsem_actions[mp->u.action.action]);
		break;
	}

	list_del(&mp->list);
	kfree(mp);
	retn = 0;

 done:
	mutex_unlock(&ctx->external->measurement_mutex);
	return retn;
}

int tsem_export_event(struct tsem_event *ep)
{
	int retn = 0;
	struct tsem_task *task = tsem_task(current);
	struct tsem_TMA_context *ctx = task->context;
	struct export_event *mp;

	if (!ctx->external)
		return 0;

	mp = kzalloc(sizeof(struct export_event), GFP_KERNEL);
	if (!mp) {
		retn = -ENOMEM;
		goto done;
	}
	mp->type = EXPORT_EVENT;
	mp->u.ep = ep;
	tsem_event_get(ep);

	mutex_lock(&ctx->external->measurement_mutex);
	list_add_tail(&mp->list, &ctx->external->measurement_list);
	mutex_unlock(&ctx->external->measurement_mutex);

	task->trust_status |= TSEM_TASK_TRUST_PENDING;
	trigger_event(ctx);

	while (task->trust_status & TSEM_TASK_TRUST_PENDING) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		if (signal_pending(current)) {
			if (sigismember(&current->pending.signal, SIGKILL) ||
			    sigismember(&current->signal->shared_pending.signal,
					SIGKILL))
				task->trust_status = TSEM_TASK_UNTRUSTED;
		}
	}

 done:
	return retn;
}

/**
 * tsem_export_action() - Exports the action taken to a security violation.
 * @event: The TSEM event type number for which the log event is being
 *	   generated.
 *
 * This function queues for export a description of an event that
 * was being disciplined.
 *
 * Return: This function returns 0 if the export was successful or
 *	   an error value if it was not.
 */
int tsem_export_action(enum tsem_event_type event)
{
	struct tsem_TMA_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = kzalloc(sizeof(struct export_event), GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = LOG_EVENT;
	exp->u.action.type = event;
	exp->u.action.action = ctx->actions[event];
	strcpy(exp->u.action.comm, current->comm);

	mutex_lock(&ctx->external->measurement_mutex);
	list_add_tail(&exp->list, &ctx->external->measurement_list);
	mutex_unlock(&ctx->external->measurement_mutex);

	trigger_event(ctx);

	return 0;
}

/**
 * tsem_export_aggregate() - Exports the hardware aggregate value.
 *
 * This function exports the hardware aggregate measurement for
 * the platform on which the TSEM LSM is being run on.
 *
 * Return: This function returns a value of 0 if the export was
 *	   successful or a non-zero return value if the export was
 *	   not successful.
 */
int tsem_export_aggregate(void)
{
	struct tsem_TMA_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = kzalloc(sizeof(struct export_event), GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = AGGREGATE_EVENT;
	memcpy(exp->u.aggregate, tsem_trust_aggregate(),
	       sizeof(exp->u.aggregate));

	mutex_lock(&ctx->external->measurement_mutex);
	list_add_tail(&exp->list, &ctx->external->measurement_list);
	mutex_unlock(&ctx->external->measurement_mutex);

	trigger_event(ctx);

	return 0;
}
