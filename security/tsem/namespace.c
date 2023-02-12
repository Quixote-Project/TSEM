// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file implements TSEM namespaces.
 */

#include "tsem.h"

static u64 context_id;

static struct workqueue_struct *release_wq;

struct lsm_blob_sizes tsem_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct tsem_task),
	.lbs_inode = sizeof(struct tsem_inode)
};

enum tsem_action_type tsem_root_actions[TSEM_EVENT_CNT] = {
	TSEM_ACTION_EPERM	/* Undefined. */
};

struct tsem_model root_model = {
	.point_mutex = __MUTEX_INITIALIZER(root_model.point_mutex),
	.point_list = LIST_HEAD_INIT(root_model.point_list),
	.state_list = LIST_HEAD_INIT(root_model.state_list),

	.trajectory_mutex = __MUTEX_INITIALIZER(root_model.trajectory_mutex),
	.trajectory_list = LIST_HEAD_INIT(root_model.trajectory_list),

	.max_forensics_count = 100,
	.forensics_mutex = __MUTEX_INITIALIZER(root_model.forensics_mutex),
	.forensics_list = LIST_HEAD_INIT(root_model.forensics_list),

	.pseudonym_mutex = __MUTEX_INITIALIZER(root_model.pseudonym_mutex),
	.pseudonym_list = LIST_HEAD_INIT(root_model.pseudonym_list)
};

struct tsem_TMA_context root_TMA_context = {
	.kref = KREF_INIT(2),
	.id = 0,
	.external = false,
	.model = &root_model
};

static struct tsem_external *allocate_external(void)
{
	int retn = -ENOMEM;
	struct tsem_external *external;
	char bufr[20 + 1];

	external = kzalloc(sizeof(struct tsem_external), GFP_KERNEL);
	if (!external)
		return NULL;

	mutex_init(&external->measurement_mutex);
	INIT_LIST_HEAD(&external->measurement_list);

	init_waitqueue_head(&external->wq);

	scnprintf(bufr, sizeof(bufr), "%llu", context_id + 1);
	external->dentry = tsem_fs_create_external(bufr);
	if (IS_ERR(external->dentry)) {
		retn = PTR_ERR(external->dentry);
		external->dentry = NULL;
	} else
		retn = 0;

	if (retn) {
		kfree(external);
		external = NULL;
	}

	return external;
}

/**
 * tsem_ns_free() - Releases the namespace model infrastructure.
 * @kref: A pointer to the reference counting structure for the namespace.
 *
 * This function is called when the last reference to a kernel
 * based TMA model structure is released.
 */
void tsem_ns_free(struct kref *kref)
{
	struct tsem_TMA_context *ctx;

	ctx = container_of(kref, struct tsem_TMA_context, kref);

	if (ctx->external) {
		tsem_fs_remove_external(ctx->external->dentry);
		kfree(ctx->external);
	} else
		tsem_model_free(ctx);

	kfree(ctx);
}

static void wq_put(struct work_struct *work)
{
	struct tsem_TMA_work *tsem_work;
	struct tsem_TMA_context *ctx;

	tsem_work = container_of(work, struct tsem_TMA_work, work);
	ctx = tsem_work->ctx;
	kref_put(&ctx->kref, tsem_ns_free);
}

/**
 * tsem_ns_get() - Obtain a reference on a TSEM TMA namespace.
 * @ctx: A pointer to the TMA modeling context for which a reference is
 *	 to be released.
 *
 * This function is called to release a reference to a TMA modeling
 * domain.
 */
void tsem_ns_put(struct tsem_TMA_context *ctx)
{
	if (kref_read(&ctx->kref) > 1) {
		kref_put(&ctx->kref, tsem_ns_free);
		return;
	}

	INIT_WORK(&ctx->work.work, wq_put);
	ctx->work.ctx = ctx;
	if (!queue_work(release_wq, &ctx->work.work))
		WARN_ON_ONCE(1);
}

/**
 * tsem_ns_put() - Obtain a reference on a TSEM TMA namespace.
 * @ctx: A pointer to the TMA modeling context for which a reference is
 *	 to be acquired.
 *
 * This function is called on each invocation of the tsem_task_alloc
 * event to obtain a reference against the current modeling domain.
 */
void tsem_ns_get(struct tsem_TMA_context *ctx)
{
	kref_get(&ctx->kref);
}

/**
 * tsem_ns_namespace() - Create a TSEM modeling namespace.
 * @event: The numeric identifer of the control message that is to
 *	   be processed.
 *
 * This function is used to create either an internally or externally
 * modeled TSEM namespace.  The boolean argument to this function
 * selects the type of namespace that is being created.  Specification
 * of an internal namespace causes the ->model pointer to be initialized
 * with a tsem_model structure.
 *
 * Return: This function returns 0 if the namespace was created and
 *	   a negative error value on error.
 */
int tsem_ns_create(enum tsem_control_type event)
{
	int retn = -ENOMEM;
	struct tsem_task *tsk = tsem_task(current);
	struct tsem_TMA_context *new_ctx;
	struct tsem_model *model = NULL;

	new_ctx = kzalloc(sizeof(struct tsem_TMA_context), GFP_KERNEL);
	if (!new_ctx)
		goto done;

	if (event == TSEM_CONTROL_INTERNAL) {
		model = tsem_model_allocate();
		if (!model)
			goto done;
		new_ctx->model = model;
	}
	if (event == TSEM_CONTROL_EXTERNAL) {
		new_ctx->external = allocate_external();
		if (!new_ctx->external)
			goto done;
	}

	kref_init(&new_ctx->kref);
	new_ctx->id = ++context_id;
	memcpy(new_ctx->actions, tsk->context->actions,
	       sizeof(new_ctx->actions));
	retn = 0;

 done:
	if (retn) {
		kfree(new_ctx->external);
		kfree(new_ctx);
		kfree(model);
	} else {
		tsk->context = new_ctx;
		if (event == TSEM_CONTROL_EXTERNAL)
			retn = tsem_export_aggregate();
		else
			retn = tsem_model_add_aggregate();
	}

	return retn;
}

/**
 * tsem_ns_init() - Initialize TSEM namespace processing.
 *
 * This function is called as part of the TSEM LSM initialization
 * process.  It initializes the workqueue that will be used to
 * conduct the asynchronous release of modeling contexts.  The
 * deferral of the namespace clean is needed in order to address
 * the fact that the /sys/fs/tsem pseudo-files cannot be done
 * in atomic context.
 *
 * Return: If the initialization succeeds a return code of 0 is returned.
 *	   A negative return value is returned on failure.
 */
int __init tsem_ns_init(void)
{
	int retn = 0;

	release_wq = create_workqueue("tsem_ns_release");
	if (IS_ERR(release_wq))
		retn = PTR_ERR(release_wq);

	return retn;
}
