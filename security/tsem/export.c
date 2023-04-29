// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements updates to an external modeling engine.
 */

#define MAGAZINE_SIZE 96

#include <linux/seq_file.h>

#include "tsem.h"

enum export_type {
	AGGREGATE_EVENT = 1,
	EXPORT_EVENT,
	EXPORT_ASYNC_EVENT,
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

static struct kmem_cache *export_cachep;

static DEFINE_SPINLOCK(magazine_lock);
static DECLARE_BITMAP(magazine_index, MAGAZINE_SIZE);

static struct export_event *export_magazine[MAGAZINE_SIZE];

static void free_export(struct export_event *exp, bool locked)
{
	unsigned int index;

	if (!locked) {
		kmem_cache_free(export_cachep, exp);
		return;
	}

	memset(exp, 0, sizeof(*exp));

	spin_lock(&magazine_lock);
	index = find_first_bit(magazine_index, MAGAZINE_SIZE);
	if (index < MAGAZINE_SIZE) {
		export_magazine[index] = exp;
		clear_bit(index, magazine_index);
	}

	/*
	 * The following memory barrier is used to cause the magazine
	 * index to be visible after the refill of the cache slot.
	 */
	smp_mb__after_atomic();

	spin_unlock(&magazine_lock);

	if (index >= MAGAZINE_SIZE)
		WARN_ONCE(true, "Refilling export magazine with no slots.\n");
}

struct export_event *allocate_export(bool locked)
{
	unsigned int index;
	struct export_event *exp = NULL;

	if (!locked)
		return kmem_cache_zalloc(export_cachep, GFP_KERNEL);

	spin_lock(&magazine_lock);
	index = find_first_zero_bit(magazine_index, MAGAZINE_SIZE);
	if (index < MAGAZINE_SIZE) {
		exp = export_magazine[index];
		set_bit(index, magazine_index);

		/*
		 * Similar to the issue noted in the refill_event_magazine()
		 * function, this barrier is used to cause the consumption
		 * of the cache entry to become visible.

		 */
		smp_mb__after_atomic();
	}
	spin_unlock(&magazine_lock);

	return exp;
}

static void trigger_event(struct tsem_context *ctx)
{
	ctx->external->have_event = true;
	wake_up_interruptible(&ctx->external->wq);
}

int tsem_export_show(struct seq_file *sf, void *v)
{
	bool locked = false;
	struct export_event *exp = NULL;
	struct tsem_context *ctx = tsem_context(current);

	if (!ctx->id)
		return -ENODATA;

	spin_lock(&ctx->external->export_lock);
	if (!list_empty(&ctx->external->export_list)) {
		exp = list_first_entry(&ctx->external->export_list,
				       struct export_event, list);
		list_del(&exp->list);
	}
	spin_unlock(&ctx->external->export_lock);

	if (!exp)
		return -ENODATA;

	seq_putc(sf, '{');
	tsem_fs_show_field(sf, "export");

	switch (exp->type) {
	case AGGREGATE_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "aggregate");
		tsem_fs_show_field(sf, "aggregate");
		tsem_fs_show_key(sf, "}", "value", "%*phN", tsem_digestsize(),
				 exp->u.aggregate);
		break;

	case EXPORT_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "event");
		tsem_fs_show_trajectory(sf, exp->u.ep);
		locked = exp->u.ep->locked;
		tsem_event_put(exp->u.ep);
		break;

	case EXPORT_ASYNC_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "async_event");
		tsem_fs_show_trajectory(sf, exp->u.ep);
		locked = exp->u.ep->locked;
		tsem_event_put(exp->u.ep);
		break;

	case LOG_EVENT:
		tsem_fs_show_key(sf, "}, ", "type", "%s", "log");
		tsem_fs_show_field(sf, "log");
		tsem_fs_show_key(sf, ",", "process", "%s", exp->u.action.comm);
		tsem_fs_show_key(sf, ",", "event", "%s",
				 tsem_names[exp->u.action.type]);
		tsem_fs_show_key(sf, "}", "action", "%s",
				 tsem_actions[exp->u.action.action]);
		break;
	}
	seq_puts(sf, "}\n");

	free_export(exp, locked);
	return 0;
}

/**
 * tsem_export_event() - Export a security event description.
 * @event: The TSEM event type number for which the log event is being
 *	   generated.
 *
 * This function queues for export to an external modeling agent a
 * security event description.
 *
 * Return: This function returns 0 if the export was successful or
 *	   an error value if it was not.
 */
int tsem_export_event(struct tsem_event *ep)
{
	int retn = 0;
	struct tsem_task *task = tsem_task(current);
	struct tsem_context *ctx = task->context;
	struct export_event *exp;

	exp = allocate_export(ep->locked);
	if (!exp) {
		pr_warn("tsem: domain %llu failed export allocation.\n",
			ctx->id);
		return -ENOMEM;
	}

	exp->type = ep->locked ? EXPORT_ASYNC_EVENT : EXPORT_EVENT;
	exp->u.ep = ep;
	tsem_event_get(ep);

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

	if (ep->locked) {
		trigger_event(ctx);
		return 0;
	}

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
	struct tsem_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = kmem_cache_zalloc(export_cachep, GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = LOG_EVENT;
	exp->u.action.type = event;
	exp->u.action.action = ctx->actions[event];
	strcpy(exp->u.action.comm, current->comm);

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

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
	struct tsem_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = kmem_cache_zalloc(export_cachep, GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = AGGREGATE_EVENT;
	memcpy(exp->u.aggregate, tsem_trust_aggregate(), tsem_digestsize());

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

	trigger_event(ctx);

	return 0;
}

/**
 * tsem export_cache_init() - Initialize the TSEM export cache.
 *
 * This function is called by the TSEM initialization function and sets
 * up a cache for export structures that are called by security event
 * descriptions that are generated in atomix context
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int __init tsem_export_cache_init(void)
{
	int cnt;

	export_cachep = kmem_cache_create("tsem_export_cache",
					 sizeof(struct export_event), 0,
					 SLAB_PANIC, 0);
	if (!export_cachep)
		return -ENOMEM;

	for (cnt = 0; cnt < MAGAZINE_SIZE; ++cnt) {
		export_magazine[cnt] = kmem_cache_zalloc(export_cachep,
							 GFP_KERNEL);
		if (!export_magazine[cnt])
			return -ENOMEM;
	}

	return 0;
}
