// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * Implements management of a TPM trust root for the in kernel TMA.
 */

#include <crypto/hash.h>
#include <linux/tpm.h>

#include "tsem.h"

#define TSEM_TRUST_ROOT 11

static u8 hardware_aggregate[WP256_DIGEST_SIZE];

static struct tpm_chip *tpm;

static struct tpm_digest *digests;


void __init generate_aggregate(struct crypto_shash *tfm)
{
	int retn = 0, lp;
	struct tpm_digest pcr;
	u8 digest[WP256_DIGEST_SIZE];
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;
	retn = crypto_shash_init(shash);
	if (retn)
		goto done;

	if (tpm_is_tpm2(tpm))
		pcr.alg_id = TPM_ALG_SHA256;
	else
		pcr.alg_id = TPM_ALG_SHA1;
	memset(pcr.digest, '\0', TPM_MAX_DIGEST_SIZE);

	for (lp = 0; lp < 8; ++lp) {
		retn = tpm_pcr_read(tpm, lp, &pcr);
		if (retn)
			goto done;
		memcpy(digest, pcr.digest, sizeof(digest));
		retn = crypto_shash_update(shash, digest, WP256_DIGEST_SIZE);
		if (retn)
			goto done;
	}
	if (!retn)
		retn = crypto_shash_final(shash, hardware_aggregate);

 done:
	if (retn)
		pr_info("Unable to generate platform aggregate\n");
}

static int __init trust_init(void)
{
	int retn = -EINVAL, lp;
	struct crypto_shash *tfm = NULL;

	tpm = tpm_default_chip();
	if (!tpm) {
		pr_info("No TPM found for event modeling.\n");
		return retn;
	}

	digests = kcalloc(tpm->nr_allocated_banks, sizeof(*digests), GFP_NOFS);
	if (!digests) {
		tpm = NULL;
		return retn;
	}
	for (lp = 0; lp < tpm->nr_allocated_banks; lp++)
		digests[lp].alg_id = tpm->allocated_banks[lp].alg_id;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		retn = PTR_ERR(tfm);
	else {
		generate_aggregate(tfm);
		retn = 0;
	}
	crypto_free_shash(tfm);

	return retn;
}

/**
 * tsem_trust_aggregate() - Return a pointer to the hardware aggregate.
 *
 * This function returns a pointer to the hardware aggregate that
 * is computed at system boot time.
 *
 * Return: A byte pointer is returned to the statically scoped array
 *	   that contains the hardware aggregate value.
 */
u8 *tsem_trust_aggregate(void)
{
	return hardware_aggregate;
}

/**
 * tsem_trust_add_point() - Add a measurement to the trust root.
 * @coefficient: A pointer to the event coefficient to be added.
 *
 * This function extends the platform configuration register being
 * used to document the hardware root of trust for internally modeled
 * domains with a security event coefficient value.
 *
 * Return: If the extension fails the error return value from the
 *	   TPM command is returned, otherwise a value of zero is
 *	   returned.
 */
int tsem_trust_add_event(u8 *coefficient)
{
	int amt, bank;

	if (!tpm)
		return 0;

	for (bank = 0; bank < tpm->nr_allocated_banks; bank++) {
		if (tpm->allocated_banks[bank].digest_size < WP256_DIGEST_SIZE)
			amt = tpm->allocated_banks[bank].digest_size;
		else
			amt = WP256_DIGEST_SIZE;
		memcpy(digests[bank].digest, coefficient, amt);
	}

	return tpm_pcr_extend(tpm, TSEM_TRUST_ROOT, digests);
}

late_initcall(trust_init);
