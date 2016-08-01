#include "pxyssl.h"

/*
 * Proxy connection context state, describes a proxy connection
 * with source and destination socket bufferevents, SSL context and
 * other session state.  One of these exists per handled proxy
 * connection.
 */

/* single dst or src socket bufferevent descriptor */
typedef struct pxy_ssl_desc {
	SSL *ssl;
	unsigned int closed : 1;
} pxy_ssl_desc_t;

/* actual proxy connection state consisting of two connection descriptors,
 * connection-wide state and the specs and options */
typedef struct pxy_conn_ctx {
	/* socket descriptor */
	int serverSock;/* real server side */
	int clientSock;/* real client side */

	/* per-connection state */
	struct pxy_ssl_desc src;
	struct pxy_ssl_desc dst;

	/* status flags */
	unsigned int immutable_cert : 1;  /* 1 if the cert cannot be changed */
	unsigned int connected : 1;       /* 0 until both ends are connected */
	unsigned int seen_req_header : 1; /* 0 until request header complete */
	unsigned int seen_resp_header : 1;  /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1;   /* 0 until Conn: close sent */
	unsigned int passthrough : 1;      /* 1 if SSL passthrough is active */
	unsigned int ocsp_denied : 1;                /* 1 if OCSP was denied */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	unsigned int sni_peek_retries : 6;       /* max 64 SNI parse retries */

	/* server name indicated by client in SNI TLS extension */
	char *sni;

	/* log strings from socket */
	char src_ip_str[32];
	char dst_ip_str[32];
	int src_port;
	int dst_port;

	/* server url */
	char servername[512];

	/* log strings from SSL context */
	char *ssl_names;
	char *ssl_orignames;

	/* content log context */
	log_content_ctx_t logctx;

	/* original destination address, family and certificate */
	struct sockaddr_in addr;
	X509 *origcrt;
} pxy_conn_ctx_t;


static int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
static void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
static SSL_SESSION * pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);
static int pxy_ossl_servername_cb(SSL *ssl, UNUSED int *al, void *arg);
static SSL_CTX* pxy_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) *chain, EVP_PKEY *key);


static pxy_conn_ctx_t* pxy_conn_ctx_new(int realServerSock, int clientSock, uint32_t ip, uint16_t port, void *peer) {
	string ipString;
	struct socketInfo *client = (struct socketInfo*)peer;
	pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t*)malloc(sizeof(pxy_conn_ctx_t));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(pxy_conn_ctx_t));

	ctx->serverSock = realServerSock;
	ctx->clientSock = clientSock;

	ctx->addr.sin_family = AF_INET;
	ipString = int_to_str(ip);
	struct hostent *server = gethostbyname(ipString.c_str());
	memcpy((char *)&ctx->addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
	ctx->addr.sin_port = htons(port);

	memset(ctx->dst_ip_str, 0, sizeof(ctx->dst_ip_str));
	strcpy(ctx->dst_ip_str, ipString.c_str());
	ctx->dst_port = port;
	ipString = int_to_str(client->addr.sin_addr.s_addr);
	memset(ctx->src_ip_str, 0, sizeof(ctx->src_ip_str));
	strcpy(ctx->src_ip_str, ipString.c_str());
	ctx->src_port = client->addr.sin_port;

	ctx->dst.ssl = NULL;
	ctx->src.ssl = NULL;

	return ctx;
}

static void pxy_conn_ctx_free(pxy_conn_ctx_t *ctx)
{
	if (ctx->ssl_names) {
		free(ctx->ssl_names);
	}

	if (ctx->ssl_orignames) {
		free(ctx->ssl_orignames);
	}

	if (ctx->origcrt) {
		X509_free(ctx->origcrt);
	}

	if (ctx->sni) {
		free(ctx->sni);
	}

	if (ctx->src.ssl) {
		SSL_shutdown(ctx->src.ssl);
	}

	if (ctx->dst.ssl) {
		SSL_shutdown(ctx->dst.ssl);
	}

	log_content_close(&ctx->logctx);

	free(ctx);
}

/*
 * Create new SSL context for outgoing connections to the original destination.
 * If hostname sni is provided, use it for Server Name Indication.
 */
static SSL* pxy_dstssl_create(pxy_conn_ctx_t *ctx)
{
	SSL *ssl;
	SSL_SESSION *sess;

	ssl = SSL_new(config.dstsslctx);
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifndef OPENSSL_NO_TLSEXT
	if (ctx->sni) {
		SSL_set_tlsext_host_name(ssl, ctx->sni);
	}
#endif /* !OPENSSL_NO_TLSEXT */

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */

	/* session resuming based on remote endpoint address and port */
	sess = (SSL_SESSION*)cachemgr_dsess_get((struct sockaddr *)&ctx->addr,
	                          (socklen_t)sizeof(ctx->addr), ctx->sni); /* new sess inst */
	if (sess) {
		SSL_set_session(ssl, sess); /* increments sess refcount */
		SSL_SESSION_free(sess);
	}

	return ssl;
}

/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef DISABLE_SSLV2_SESSION_CACHE
#define MAYBE_UNUSED 
#else /* !DISABLE_SSLV2_SESSION_CACHE */
#define MAYBE_UNUSED UNUSED
#endif /* !DISABLE_SSLV2_SESSION_CACHE */
static int pxy_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DISABLE_SSLV2_SESSION_CACHE
	/* Session resumption seems to fail for SSLv2 with protocol
	 * parsing errors, so we disable caching for SSLv2. */
	if (SSL_version(ssl) == SSL2_VERSION) {
		log_message(WARNNING_LOG, "Warning: Session resumption denied to SSLv2 client.");
		return 0;
	}
#endif /* DISABLE_SSLV2_SESSION_CACHE */
	cachemgr_ssess_set(sess);
	return 0;
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
static SSL_SESSION* pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen, int *copy)
{
	SSL_SESSION *sess;

	log_message(INFO_LOG, "===> OpenSSL get session callback:\n");

	*copy = 0; /* SSL should not increment reference count of session */
	sess = (SSL_SESSION*)cachemgr_ssess_get(id, idlen);

	log_message(INFO_LOG, "SSL session cache: %s\n", sess ? "HIT" : "MISS");
	return sess;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
static void pxy_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
	cachemgr_ssess_del(sess);
}

/*
 * OpenSSL servername callback, called when OpenSSL receives a servername
 * TLS extension in the clientHello.  Must switch to a new SSL_CTX with
 * a different certificate if we want to replace the server cert here.
 * We generate a new certificate if the current one does not match the
 * supplied servername.  This should only happen if the original destination
 * server supplies a certificate which does not match the server name we
 * indicate to it.
 */
static int pxy_ossl_servername_cb(SSL *ssl, UNUSED int *al, void *arg)
{
	pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t*)arg;
	const char *sn;
	X509 *sslcrt;

	if (!(sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
		return SSL_TLSEXT_ERR_NOACK;

	/* generate a new certificate with sn as additional altSubjectName
	 * and replace it both in the current SSL ctx and in the cert cache */
	if (!ctx->immutable_cert && !ssl_x509_names_match((sslcrt = SSL_get_certificate(ssl)), sn)) {
		X509 *newcrt;
		SSL_CTX *newsslctx;

		newcrt = ssl_x509_forge(config.cacrt, config.cakey,
		                        sslcrt, sn, config.key);
		if (!newcrt) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		cachemgr_fkcrt_set(ctx->origcrt, newcrt);

		newsslctx = pxy_srcsslctx_create(ctx, newcrt, config.chain, config.key);
		if (!newsslctx) {
			X509_free(newcrt);
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		SSL_set_SSL_CTX(ssl, newsslctx); /* decr's old incr new refc */
		SSL_CTX_free(newsslctx);
		X509_free(newcrt);
	}

	return SSL_TLSEXT_ERR_OK;
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX* pxy_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) *chain, EVP_PKEY *key) {
	SSL_CTX *sslctx = SSL_CTX_new(SSLv23_method());
	if (!sslctx)
		return NULL;
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	SSL_CTX_set_options(sslctx,
	                    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif /* SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */
#ifdef DISABLE_SSLV2_SERVER
	SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#endif /* DISABLE_SSLV2_SERVER */
	SSL_CTX_set_cipher_list(sslctx, config.ciphers);
	SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb);
	SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb);
	SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb);
	SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER |
	                                       SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
	SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
	                                       sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
#ifndef OPENSSL_NO_TLSEXT
	SSL_CTX_set_tlsext_servername_callback(sslctx, pxy_ossl_servername_cb);
	SSL_CTX_set_tlsext_servername_arg(sslctx, ctx);
#endif /* !OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_DH
	if (config.dh) {
		SSL_CTX_set_tmp_dh(sslctx, config.dh);
	} else if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA) {
		SSL_CTX_set_tmp_dh_callback(sslctx, ssl_tmp_dh_callback);
	}
#endif /* !OPENSSL_NO_DH */
	SSL_CTX_use_certificate(sslctx, crt);
	SSL_CTX_use_PrivateKey(sslctx, key);
	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *c = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(c); /* next call consumes a reference */
		SSL_CTX_add_extra_chain_cert(sslctx, c);
	}

	

	return sslctx;
}

static cert_t* pxy_srccert_create(pxy_conn_ctx_t *ctx) {
	cert_t *cert = NULL;

	if (ctx->origcrt && config.key) {
		cert = cert_new();

		cert->crt = (x509_st*)cachemgr_fkcrt_get(ctx->origcrt);
		if (cert->crt) {
			log_message(INFO_LOG, "Certificate cache: HIT\n");
		} else {
			log_message(INFO_LOG, "Certificate cache: MISS\n");
			cert->crt = ssl_x509_forge(config.cacrt,
			                           config.cakey,
			                           ctx->origcrt, NULL,
			                           config.key);
			cachemgr_fkcrt_set(ctx->origcrt, cert->crt);
		}
		cert_set_key(cert, config.key);
		cert_set_chain(cert, config.chain);
	}

	return cert;
}

/*
 * Create new SSL context for the incoming connection, based on the original
 * destination SSL certificate.
 * Returns NULL if no suitable certificate could be found.
 */
static SSL* pxy_srcssl_create(pxy_conn_ctx_t *ctx, SSL *origssl) {
	cert_t *cert;

	cachemgr_dsess_set((struct sockaddr*)&ctx->addr,
	                   (socklen_t)sizeof(ctx->addr), ctx->sni,
	                   SSL_get0_session(origssl));

	ctx->origcrt = SSL_get_peer_certificate(origssl);

	cert = pxy_srccert_create(ctx);
	if (!cert)
		return NULL;

	SSL_CTX *sslctx = pxy_srcsslctx_create(ctx, cert->crt, cert->chain,
	                                       cert->key);
	cert_free(cert);
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}
	SSL *ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
	return ssl;
}

int do_ssl_mitm_handshake(pxy_conn_ctx_t *ctx) {
	
	ctx->dst.ssl = pxy_dstssl_create(ctx);
	if (!ctx->dst.ssl) {
		log_message(ERROR_LOG, "Error creating SSL");
		return 1;
	}

	SSL_set_fd(ctx->dst.ssl, ctx->serverSock);/* attach the socket descriptor */
	if ( SSL_connect(ctx->dst.ssl) == -1 ) {
		log_message(ERROR_LOG, "SSL_connect failed.");
		return 1;
	}

	ctx->src.ssl = pxy_srcssl_create(ctx, ctx->dst.ssl);
	if (!ctx->src.ssl) {
		log_message(ERROR_LOG, "Error creating SSL");
		return 1;
	}

	SSL_set_fd(ctx->src.ssl, ctx->clientSock);
	if (SSL_accept(ctx->src.ssl) == -1) {
		log_message(ERROR_LOG, "SSL_accept failed.");
		return 1;
	}
	

	return 0;
}

void do_ssl_proxy(int realServerSock, int clientSock, uint32_t ip, uint16_t port, void *peer) {
	const char *cn;
	fd_set readfds;
	char buffer[16384];
	int result, recvd, nfds = max(realServerSock, clientSock)+1;
	pxy_conn_ctx_t *ctx = pxy_conn_ctx_new(realServerSock, clientSock, ip, port, peer);

	result = do_ssl_mitm_handshake(ctx);
	if (result) {
		pxy_conn_ctx_free(ctx);
		return;
	}

	if (!(cn = SSL_get_servername(ctx->src.ssl, TLSEXT_NAMETYPE_host_name))) {
		pxy_conn_ctx_free(ctx);
		return;
	}
	memset(ctx->servername, 0, sizeof(ctx->servername));
	strcpy(ctx->servername, cn);
	log_content_open(&ctx->logctx, ctx->src_ip_str, ctx->src_port, ctx->dst_ip_str, ctx->dst_port, ctx->servername);

	set_fds(ctx->serverSock, ctx->clientSock, &readfds);

	while((result = select(nfds, &readfds, 0, 0, 0)) > 0) {
		logbuf_t *lb;
		
		if(FD_ISSET(ctx->serverSock, &readfds)) {
			recvd = SSL_read(ctx->dst.ssl, buffer, sizeof(buffer));
			if(recvd <= 0)
				break;
			SSL_write(ctx->src.ssl, buffer, recvd);

			lb = logbuf_new_alloc(recvd, -1, NULL);
			memcpy(lb->buf, buffer, recvd);
			log_content_submit(&ctx->logctx, lb, 0);
		}

		if(FD_ISSET(ctx->clientSock, &readfds)) {
			recvd = SSL_read(ctx->src.ssl, buffer, sizeof(buffer));
			if(recvd <= 0)
				break;
			SSL_write(ctx->dst.ssl, buffer, recvd);

			lb = logbuf_new_alloc(recvd, -1, NULL);
			memcpy(lb->buf, buffer, recvd);
			log_content_submit(&ctx->logctx, lb, 1);
		}
		set_fds(realServerSock, clientSock, &readfds);
	}

	
	pxy_conn_ctx_free(ctx);
}


