#ifndef _Z3FOLD_H_
#define _Z3FOLD_H_

#include <linux/types.h>

struct z3fold_pool;

struct z3fold_ops {
	int (*evict)(struct z3fold_pool *pool, unsigned long handle);
};

struct z3fold_pool *z3fold_create_pool(gfp_t gfp, struct z3fold_ops *ops);
void z3fold_destroy_pool(struct z3fold_pool *pool);
int z3fold_alloc(struct z3fold_pool *pool, size_t size, gfp_t gfp,
	unsigned long *handle);
void z3fold_free(struct z3fold_pool *pool, unsigned long handle);
int z3fold_reclaim_page(struct z3fold_pool *pool, unsigned int retries);
void *z3fold_map(struct z3fold_pool *pool, unsigned long handle);
void z3fold_unmap(struct z3fold_pool *pool, unsigned long handle);
u64 z3fold_get_pool_size(struct z3fold_pool *pool);

#endif /* _Z3FOLD_H_ */
