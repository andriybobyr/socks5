#ifndef CACHEDSESS_H
#define CACHEDSESS_H

#include "main.h"
#include "cache.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

typedef void * cache_val_t;
typedef void * cache_key_t;

void cachedsess_init_cb(struct cache *) NONNULL(1);

cache_key_t cachedsess_mkkey(const struct sockaddr *, const socklen_t,
                             const char *) NONNULL(1) WUNRES;
cache_val_t cachedsess_mkval(SSL_SESSION *) NONNULL(1) WUNRES;

#endif /* !CACHEDSESS_H */

/* vim: set noet ft=c: */
