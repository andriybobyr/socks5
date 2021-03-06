#ifndef CACHEFKCRT_H
#define CACHEFKCRT_H

#include "cache.h"
#include "attrib.h"
#include "main.h"

typedef void * cache_val_t;
typedef void * cache_key_t;

void cachefkcrt_init_cb(struct cache *) NONNULL(1);

cache_key_t cachefkcrt_mkkey(X509 *) NONNULL(1) WUNRES;
cache_val_t cachefkcrt_mkval(X509 *) NONNULL(1) WUNRES;

#endif /* !CACHEFKCRT_H */

