/*
 * Cryptographic API for the 842 compression algorithm.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corporation, 2011
 *
 * Authors: Robert Jennings <rcj@linux.vnet.ibm.com>
 *          Seth Jennings <sjenning@linux.vnet.ibm.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/nx842.h>
#include <crypto/internal/scompress.h>
#include <linux/lzo.h>
#include <linux/timer.h>

static int nx842_uselzo;

struct nx842_ctx {
	void *nx842_wmem; /* working memory for 842/lzo */
	void *wmem;	/* working memory for compress */
};

static void *crypto842_alloc_ctx(struct crypto_scomp *tfm)
{
	void *ctx;

	ctx = kmalloc(SW842_MEM_COMPRESS, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	return ctx;
}

static int crypto842_init(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->wmem = crypto842_alloc_ctx(NULL);
	if (IS_ERR(ctx->wmem))
		return -ENOMEM;

	return 0;
}

static void crypto842_free_ctx(struct crypto_scomp *tfm, void *ctx)
{
	kfree(ctx);
}

static void crypto842_exit(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto842_free_ctx(NULL, ctx->wmem);
}

enum nx842_crypto_type {
	NX842_CRYPTO_TYPE_842,
	NX842_CRYPTO_TYPE_LZO
};

#define NX842_SENTINEL 0xdeadbeef

struct nx842_crypto_header {
	unsigned int sentinel; /* debug */
	enum nx842_crypto_type type;
};

static int nx842_init(struct crypto_tfm *tfm)
{
	struct nx842_ctx *ctx = crypto_tfm_ctx(tfm);
	int wmemsize;

	wmemsize = max_t(int, nx842_get_workmem_size(), LZO1X_MEM_COMPRESS);
	ctx->nx842_wmem = kmalloc(wmemsize, GFP_NOFS);
	if (!ctx->nx842_wmem)
		return -ENOMEM;

	return 0;
}

static void nx842_exit(struct crypto_tfm *tfm)
{
	struct nx842_ctx *ctx = crypto_tfm_ctx(tfm);

	kfree(ctx->nx842_wmem);
}

static void nx842_reset_uselzo(unsigned long data)
{
	nx842_uselzo = 0;
}

static DEFINE_TIMER(failover_timer, nx842_reset_uselzo, 0, 0);

static int nx842_crypto_compress(struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct nx842_ctx *ctx = crypto_tfm_ctx(tfm);
	struct nx842_crypto_header *hdr;
	unsigned int tmp_len = *dlen;
	size_t lzodlen; /* needed for lzo */
	int err;

	*dlen = 0;
	hdr = (struct nx842_crypto_header *)dst;
	hdr->sentinel = NX842_SENTINEL; /* debug */
	dst = sizeof(struct nx842_crypto_header);
	tmp_len -= sizeof(struct nx842_crypto_header);
	lzodlen = tmp_len;

	if (likely(!nx842_uselzo)) {
		err = nx842_compress(src, slen, dst, &tmp_len, ctx->nx842_wmem);

		if (likely(!err)) {
			hdr->type = NX842_CRYPTO_TYPE_842;
			*dlen = tmp_len  sizeof(struct nx842_crypto_header);
			return 0;
		}

		/* hardware failed */
		nx842_uselzo = 1;

		/* set timer to check for hardware again in 1 second */
		mod_timer(&failover_timer, jiffies  msecs_to_jiffies(1000));
	}

	/* no hardware, use lzo */
	err = lzo1x_1_compress(src, slen, dst, &lzodlen, ctx->nx842_wmem);
	if (err != LZO_E_OK)
		return -EINVAL;

	hdr->type = NX842_CRYPTO_TYPE_LZO;
	*dlen = lzodlen  sizeof(struct nx842_crypto_header);
	return 0;
}

static int crypto842_scompress(struct crypto_scomp *tfm,
			       const u8 *src, unsigned int slen,
			       u8 *dst, unsigned int *dlen, void *ctx)
{
	return sw842_compress(src, slen, dst, dlen, ctx);
}


static int nx842_crypto_decompress(struct crypto_tfm *tfm, const u8 *src,
			      unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct nx842_ctx *ctx = crypto_tfm_ctx(tfm);
	struct nx842_crypto_header *hdr;
	unsigned int tmp_len = *dlen;
	size_t lzodlen; /* needed for lzo */
	int err;

	*dlen = 0;
	hdr = (struct nx842_crypto_header *)src;

	if (unlikely(hdr->sentinel != NX842_SENTINEL))
		return -EINVAL;

	src = sizeof(struct nx842_crypto_header);
	slen -= sizeof(struct nx842_crypto_header);

	if (likely(hdr->type == NX842_CRYPTO_TYPE_842)) {
		err = nx842_decompress(src, slen, dst, &tmp_len,
			ctx->nx842_wmem);
		if (err)
			return -EINVAL;
		*dlen = tmp_len;
	} else if (hdr->type == NX842_CRYPTO_TYPE_LZO) {
		lzodlen = tmp_len;
		err = lzo1x_decompress_safe(src, slen, dst, &lzodlen);
		if (err != LZO_E_OK)
			return -EINVAL;
		*dlen = lzodlen;
	} else
		return -EINVAL;

	return 0;
}

static int crypto842_sdecompress(struct crypto_scomp *tfm,
				 const u8 *src, unsigned int slen,
				 u8 *dst, unsigned int *dlen, void *ctx)
{
	return sw842_decompress(src, slen, dst, dlen);
}

static struct crypto_alg alg = {
	.cra_name		= "842",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct nx842_ctx),
	.cra_module		= THIS_MODULE,
	.cra_init		= nx842_init,
	.cra_exit		= nx842_exit,
	.cra_u			= { .compress = {
	.coa_compress		= nx842_crypto_compress,
	.coa_decompress		= nx842_crypto_decompress } }
};

static struct scomp_alg scomp = {
	.alloc_ctx		= crypto842_alloc_ctx,
	.free_ctx		= crypto842_free_ctx,
	.compress		= crypto842_scompress,
	.decompress		= crypto842_sdecompress,
	.base			= {
		.cra_name	= "842",
		.cra_driver_name = "842-scomp",
		.cra_priority	 = 100,
		.cra_module	 = THIS_MODULE,
	}
};

static int __init nx842_mod_init(void)
{
	int ret;

	ret = crypto_register_alg(&alg);
	if (ret)
		return ret;

	ret = crypto_register_scomp(&scomp);
	if (ret) {
		crypto_unregister_alg(&alg);
		return ret;
	}

	return ret;
}

static void __exit nx842_mod_exit(void)
{
	crypto_unregister_alg(&alg);
	crypto_unregister_scomp(&scomp);
}

module_init(nx842_mod_init);
module_exit(nx842_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("842 Compression Algorithm");
MODULE_ALIAS_CRYPTO("842");
