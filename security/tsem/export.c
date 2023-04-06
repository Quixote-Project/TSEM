// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements updates to an external modeling engine.
 */

#include <linux/seq_file.h>

#include "tsem.h"

enum export_type {
	AGGREGATE_EVENT = 1,
	EXPORT_EVENT,
	LOG_EVENT
};

struct action_description {
	enum export_type type;
	enum tsem_action_type action;
	char comm[TASK_COMM_LEN];
};

struct export_event {
	struct list_head list;
	enum export_type type;
	union {
		u8 *aggregate[HASH_MAX_DIGESTSIZE];
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

int tsem_export_show(struct seq_file *sf, void *v)
{
	ssize_t retn = -ENODATA;
	struct export_event *mp;
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (!ctx->id)
		return -EPERM;

	mutex_lock(&ctx->external->export_mutex);
	if (list_empty(&ctx->external->export_list))
		goto done;
	mp = list_first_entry(&ctx->external->export_list, struct export_event,
			      list);

	seq_putc(sf, '{');
	tsem_fs_show_field(sf, "export");

	switch (mp->type) {
	case AGGREGATE_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "aggregate");
		tsem_fs_show_field(sf, "aggregate");
		tsem_fs_show_key(sf, "}", "value", "%*phN", tsem_digestsize(),
				 mp->u.aggregate);
		break;

	case EXPORT_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "event");
		tsem_fs_show_trajectory(sf, mp->u.ep);
		tsem_event_put(mp->u.ep);
		break;

	case LOG_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "log");
		tsem_fs_show_field(sf, "log");
		tsem_fs_show_key(sf, ",", "process", "%s", mp->u.action.comm);
		tsem_fs_show_key(sf, ",", "event", "%s",
				 tsem_names[mp->u.action.type]);
		tsem_fs_show_key(sf, "}", "action", "%s",
				 tsem_actions[mp->u.action.action]);
		break;
	}

	seq_puts(sf, "}\n");

	list_del(&mp->list);
	kfree(mp);
	retn = 0;

 done:
	mutex_unlock(&ctx->external->export_mutex);
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

	mp = kzalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp) {
		retn = -ENOMEM;
		goto done;
	}
	mp->type = EXPORT_EVENT;
	mp->u.ep = ep;
	tsem_event_get(ep);

	mutex_lock(&ctx->external->export_mutex);
	list_add_tail(&mp->list, &ctx->external->export_list);
	mutex_unlock(&ctx->external->export_mutex);

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

	exp = kzalloc(sizeof(*exp), GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = LOG_EVENT;
	exp->u.action.type = event;
	exp->u.action.action = ctx->actions[event];
	strcpy(exp->u.action.comm, current->comm);

	mutex_lock(&ctx->external->export_mutex);
	list_add_tail(&exp->list, &ctx->external->export_list);
	mutex_unlock(&ctx->external->export_mutex);

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

	exp = kzalloc(sizeof(*exp), GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = AGGREGATE_EVENT;
	memcpy(exp->u.aggregate, tsem_trust_aggregate(), tsem_digestsize());

	mutex_lock(&ctx->external->export_mutex);
	list_add_tail(&exp->list, &ctx->external->export_list);
	mutex_unlock(&ctx->external->export_mutex);

	trigger_event(ctx);

	return 0;
}
