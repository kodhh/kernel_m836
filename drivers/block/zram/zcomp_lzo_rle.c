/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/lzo.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

#include "zcomp_lzo_rle.h"

static void *lzo_rle_create(gfp_t flags)
{
	void *ret;

	ret = kmalloc(LZO1X_MEM_COMPRESS, flags);
	if (!ret)
		ret = __vmalloc(LZO1X_MEM_COMPRESS,
				flags | __GFP_HIGHMEM,
				PAGE_KERNEL);
	return ret;
}

static void lzo_rle_destroy(void *private)
{
	kvfree(private);
}

static int lzo_rle_compress(const unsigned char *src, unsigned char *dst,
		size_t *dst_len, void *private)
{
	int ret = lzorle1x_1_compress(src, PAGE_SIZE, dst, dst_len, private);
	return ret == LZO_E_OK ? 0 : ret;
}

static int lzo_rle_decompress(const unsigned char *src, size_t src_len,
		unsigned char *dst)
{
	size_t dst_len = PAGE_SIZE;
	int ret = lzo1x_decompress_safe(src, src_len, dst, &dst_len);
	return ret == LZO_E_OK ? 0 : ret;
}

struct zcomp_backend zcomp_lzo_rle = {
	.compress = lzo_rle_compress,
	.decompress = lzo_rle_decompress,
	.create = lzo_rle_create,
	.destroy = lzo_rle_destroy,
	.name = "lzo-rle",
};
