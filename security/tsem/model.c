// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements the an kernel modeling agent.
 */

#include <linux/list_sort.h>

#include "tsem.h"

struct state_point {
	struct list_head list;
	struct tsem_event_point *point;
};

struct pseudonym {
	struct list_head list;
	u8 mapping[HASH_MAX_DIGESTSIZE];
};

static int generate_pseudonym(struct tsem_file *ep, u8 *pseudonym)
{
	int retn = 0;
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, (u8 *) &ep->name_length,
				   sizeof(ep->name_length));
	if (retn)
		goto done;

	retn = crypto_shash_finup(shash, ep->name, tsem_digestsize(),
				  pseudonym);
 done:
	return retn;
}

static int have_point(u8 *point)
{
	int retn = 0;
	struct tsem_event_point *entry;
	struct tsem_TMA_context *ctx = tsem_context(current);
	struct tsem_model *model = ctx->model;

	mutex_lock(&model->point_mutex);
	list_for_each_entry(entry, &model->point_list, list) {
		if (memcmp(entry->point, point, tsem_digestsize()) == 0) {
			if (entry->valid)
				retn = 1;
			else
				retn = -EPERM;
			goto done;
		}
	}

 done:
	mutex_unlock(&model->point_mutex);
	return retn;
}

static int add_event_point(u8 *point, bool valid)
{
	int retn = 1;
	struct tsem_event_point *entry;
	struct state_point *state;
	struct tsem_model *model = tsem_model(current);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		goto done;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto done;
	state->point = entry;

	mutex_lock(&model->point_mutex);
	memcpy(entry->point, point, tsem_digestsize());
	entry->valid = valid;
	list_add_tail(&entry->list, &model->point_list);
	list_add_tail(&state->list, &model->state_list);
	++model->point_count;
	mutex_unlock(&model->point_mutex);
	retn = 0;

 done:
	return retn;
}

static int add_trajectory_point(struct tsem_event *ep)
{
	struct tsem_model *model = tsem_model(current);

	ep->pid = 0;
	tsem_event_get(ep);

	mutex_lock(&model->trajectory_mutex);
	list_add_tail(&ep->list, &model->trajectory_list);
	++model->trajectory_count;
	mutex_unlock(&model->trajectory_mutex);

	return 0;
}

static int add_forensic_point(struct tsem_event *ep)
{
	struct tsem_model *model = tsem_model(current);

	if (model->forensics_count == model->max_forensics_count)
		return -E2BIG;

	ep->pid = 0;
	tsem_event_get(ep);

	mutex_lock(&model->forensics_mutex);
	list_add_tail(&ep->list, &model->forensics_list);
	++model->forensics_count;
	mutex_unlock(&model->forensics_mutex);

	return 0;
}

static int get_host_measurement(u8 *id, u8 *digest)
{
	int retn;
	struct tsem_model *model = tsem_model(current);
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, model->base, tsem_digestsize());
	if (retn)
		goto done;

	retn = crypto_shash_finup(shash, id, tsem_digestsize(), digest);

 done:
	return retn;
}

static int update_events_measurement(u8 *id)
{
	int retn;
	u8 digest[HASH_MAX_DIGESTSIZE];
	struct tsem_TMA_context *ctx = tsem_context(current);
	struct tsem_model *model = ctx->model;
	SHASH_DESC_ON_STACK(shash, tfm);

	retn = get_host_measurement(id, digest);
	if (retn)
		goto done;

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	retn = crypto_shash_update(shash, model->measurement,
				   tsem_digestsize());
	if (retn)
		goto done;

	retn = crypto_shash_finup(shash, digest, tsem_digestsize(),
				  model->measurement);
	if (retn)
		goto done;

	if (!tsem_context(current)->id)
		retn = tsem_trust_add_event(digest);

 done:
	return retn;
}

static int state_sort(void *priv, const struct list_head *a,
		      const struct list_head *b)
{
	unsigned int lp, retn;
	struct state_point *ap = container_of(a, struct state_point, list);
	struct state_point *bp = container_of(b, struct state_point, list);

	for (lp = 0; lp < tsem_digestsize() - 1; ++lp) {
		if (ap->point->point[lp] == bp->point->point[lp])
			continue;
		retn = ap->point->point[lp] > bp->point->point[lp];
		goto done;
	}
	retn = ap->point->point[lp] > bp->point->point[lp];

 done:
	return retn;
}

/**
 * tesm_model_compute_state() - Calculate a security model state value.
 *
 * This value is used to trigger the computation of the security
 * state description value for a modeling domain.
 */
void tsem_model_compute_state(void)
{
	u8 state[HASH_MAX_DIGESTSIZE];
	int retn;
	struct state_point *entry;
	struct tsem_model *model = tsem_model(current);
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	memset(state, '\0', sizeof(state));
	retn = crypto_shash_update(shash, state, tsem_digestsize());
	if (retn)
		goto done;

	retn = get_host_measurement(tsem_trust_aggregate(), state);
	if (retn)
		goto done;

	retn = crypto_shash_finup(shash, state, tsem_digestsize(), state);
	if (retn)
		goto done;

	mutex_lock(&model->point_mutex);
	list_sort(NULL, &model->state_list, state_sort);

	memcpy(model->state, state, tsem_digestsize());
	list_for_each_entry(entry, &model->state_list, list) {
		if (get_host_measurement(entry->point->point, state))
			goto done_unlock;

		if (crypto_shash_init(shash))
			goto done_unlock;
		if (crypto_shash_update(shash, model->state,
					tsem_digestsize()))
			goto done_unlock;
		if (crypto_shash_finup(shash, state, tsem_digestsize(),
				       model->state))
			goto done_unlock;
	}

 done_unlock:
	mutex_unlock(&model->point_mutex);
 done:
	if (retn)
		memset(model->state, '\0', tsem_digestsize());
}

/**
 * tsem_model_has_pseudonym() - Test for a model pseudonym.
 * @tsip: A pointer to the TSEM inode security structure.
 * @ep: A pointer to the TSEM event description structure.
 *
 * This function is used to test whether a pseudonym has been
 * declared for a modeling domain.  It is up to the caller to
 * populate the event description structure with a suitable
 * value for the pseudonym digest.
 *
 * Return: If an error occurs during the pseudonym probe a negative
 *	   return value is returned.  A zero return value indicates that
 *	   a pseudonym was not present.  A value of one indicates that a
 *	   pseudonym has been defined.
 */
int tsem_model_has_pseudonym(struct tsem_inode *tsip, struct tsem_file *ep)
{
	int retn = 0;
	u8 pseudo_mapping[HASH_MAX_DIGESTSIZE];
	struct tsem_model *model = tsem_model(current);
	struct pseudonym *entry;

	retn = generate_pseudonym(ep, pseudo_mapping);
	if (retn)
		goto done;

	mutex_lock(&model->pseudonym_mutex);
	list_for_each_entry(entry, &model->pseudonym_list, list) {
		if (!memcmp(entry->mapping, pseudo_mapping,
			    tsem_digestsize())) {
			retn = 1;
			goto done;
		}
	}
	retn = 0;

 done:
	mutex_unlock(&model->pseudonym_mutex);
	return retn;
}

/**
 * tesm_model_event() - Inject a security event into a modeling domain.
 * @ep: A pointer to the event description structure.
 *
 * This function is the entry point for the in kernel Trusted Modeling
 * Agent (TMA).  It takes a description of an event encoded in a
 * tsem_event structure and generates and updates the security model
 * description.
 *
 * Return: If an error occurs during the injection of an event into a
 *	   model a negative error value is returned.  A value of zero
 *	   is returned if the event was successfully modeled.  The
 *	   security status of the event is returned by encoding the value
 *	   in the bad_COE member of the tsem_task structure.
 */
int tsem_model_event(struct tsem_event *ep)
{
	int retn;
	struct tsem_task *task = tsem_task(current);
	struct tsem_TMA_context *ctx = task->context;

	retn = have_point(ep->mapping);
	if (retn) {
		if (retn != 1)
			task->trust_status = TSEM_TASK_UNTRUSTED;
		return 0;
	}

	retn = update_events_measurement(ep->mapping);
	if (retn)
		goto done;

	if (ctx->sealed) {
		retn = add_event_point(ep->mapping, false);
		if (!retn)
			retn = add_forensic_point(ep);
		task->trust_status = TSEM_TASK_UNTRUSTED;
	} else {
		retn = add_event_point(ep->mapping, true);
		if (!retn)
			retn = add_trajectory_point(ep);
	}
	if (retn)
		retn = -EPERM;

 done:
	return retn;
}

/**
 * tesm_model_load_point() - Load a security state event into a model.
 * @point: A pointer to the array containing the security state
 *	   point to be added to the model.
 *
 * This function takes the binary representation of a security state
 * point and loads it into the current model domain.
 *
 * Return: If an error occurs during the processing of the security state
 *	   point a negative return value is returned.  A return value of
 *	   zero indicates the point was successfully loaded into the domain.
 */
int tsem_model_load_point(u8 *point)
{
	ssize_t retn = 0;
	struct tsem_TMA_context *ctx = tsem_context(current);

	if (have_point(point))
		goto done;
	if (add_event_point(point, true)) {
		retn = -ENOMEM;
		goto done;
	}

	if (!ctx->model->have_aggregate) {
		ctx->model->have_aggregate = true;
		retn = update_events_measurement(tsem_trust_aggregate());
		if (retn)
			goto done;
	}

	retn = update_events_measurement(point);

done:
	return retn;

}

/**
 * tesm_model_load_pseudonym() - Load a pseudonym state point to a model.
 * @mapping: A pointer to the array containing the pseudonym state
 *	     point that is to be added to the model.
 *
 * This function takes the binary representation of a file pseudonym
 * and declares the presence of the pseudonym in the modeling domain.
 *
 * Return: If an error occurs during the processing of the pseudonym
 *	   state point a negative return value is returned.  A return
 *	   value of zero indicates the point was successfully loaded
 *	   into the model.
 */
int tsem_model_load_pseudonym(u8 *mapping)
{
	struct pseudonym *psp = NULL;
	struct tsem_model *model = tsem_model(current);

	psp = kzalloc(sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return -ENOMEM;
	memcpy(psp->mapping, mapping, tsem_digestsize());

	mutex_lock(&model->pseudonym_mutex);
	list_add_tail(&psp->list, &model->pseudonym_list);
	mutex_unlock(&model->pseudonym_mutex);
	return 0;
}

/**
 * tesm_model_load_base() - Load a model base point.
 * @mapping: A pointer to the array containing the base point to be
 *	     set for the model.
 *
 * This function takes the binary representation of a base point and
 * sets this point as the base point for the model.
 */
void tsem_model_load_base(u8 *mapping)
{
	struct tsem_model *model = tsem_model(current);

	memcpy(model->base, mapping, tsem_digestsize());
}

/**
 * tesm_model_add_aggregate() - Add the hardware aggregate to a model.
 *
 * This function adds the hardware aggregate value to an internally
 * modeled security domain.
 *
 * Return: If an error occurs during the injection of the aggregate
 *	   value into the model a negative error value is returned.
 *	   A return value of zero indicates the aggregate was
 *	   successfully added.
 */
int tsem_model_add_aggregate(void)
{
	return update_events_measurement(tsem_trust_aggregate());
}

/**
 * tsem_model_allocate() - Allocates a kernel TMA modeling structure.
 *
 * This function allocates and initializes a tsem_model structure
 * that is used to hold modeling information for an in kernel
 * modeling domain.
 *
 * Return: On success a pointer to the model description structure is
 *	   returned.  If an error occurs an error return value is
 *	   encoded in the returned pointer.
 */
struct tsem_model *tsem_model_allocate(void)
{
	struct tsem_model *model = NULL;

	model = kzalloc(sizeof(*model), GFP_KERNEL);
	if (!model)
		return NULL;

	mutex_init(&model->point_mutex);
	INIT_LIST_HEAD(&model->point_list);
	INIT_LIST_HEAD(&model->state_list);

	mutex_init(&model->trajectory_mutex);
	INIT_LIST_HEAD(&model->trajectory_list);

	model->max_forensics_count = 100;
	mutex_init(&model->forensics_mutex);
	INIT_LIST_HEAD(&model->forensics_list);

	mutex_init(&model->pseudonym_mutex);
	INIT_LIST_HEAD(&model->pseudonym_list);

	return model;
}

/**
 * tsem_model_free() - Frees an a kernel TMA description structure.
 * @ctx: A pointer to the TMA modeling description structure whose
 *	 model definition is to be deleted.
 *
 * This function is called when the last reference to a kernel
 * based TMA model description structure is released.
 */
void tsem_model_free(struct tsem_TMA_context *ctx)
{
	unsigned int cnt;
	struct tsem_event_point *centry, *tmp_centry;
	struct state_point *state, *tmp_state;
	struct tsem_event *tentry, *tmp_tentry;
	struct pseudonym *sentry, *tmp_sentry;
	struct tsem_model *model = ctx->model;

	cnt = 0;
	list_for_each_entry_safe(centry, tmp_centry, &model->point_list,
				 list) {
		list_del(&centry->list);
		kfree(centry);
		++cnt;
	}

	cnt = 0;
	list_for_each_entry_safe(state, tmp_state, &model->state_list,
				 list) {
		list_del(&state->list);
		kfree(state);
		++cnt;
	}

	cnt = 0;
	list_for_each_entry_safe(tentry, tmp_tentry, &model->trajectory_list,
				 list) {
		list_del(&tentry->list);
		tsem_event_put(tentry);
		++cnt;
	}

	cnt = 0;
	list_for_each_entry_safe(sentry, tmp_sentry, &model->pseudonym_list,
				 list) {
		list_del(&sentry->list);
		kfree(sentry);
		++cnt;
	}

	if (ctx->sealed) {
		cnt = 0;
		list_for_each_entry_safe(tentry, tmp_tentry,
					 &model->forensics_list, list) {
			list_del(&tentry->list);
			tsem_event_put(tentry);
			++cnt;
		}
	}

	kfree(model);
}
