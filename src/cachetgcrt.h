#ifndef CACHETGCRT_H
#define CACHETGCRT_H

#include "main.h"
#include "cache.h"

typedef void * cache_val_t;
typedef void * cache_key_t;

void cachetgcrt_init_cb(struct cache *) NONNULL(1);

cache_key_t cachetgcrt_mkkey(const char *) NONNULL(1) WUNRES;
cache_val_t cachetgcrt_mkval(struct cert *valcrt) NONNULL(1) WUNRES;

#endif /* !CACHETGCRT_H */

/* vim: set noet ft=c: */
