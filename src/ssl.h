#ifndef SSL_H
#define SSL_H

#include "attrib.h"
#include "main.h"

/*
 * ECDH is disabled when building against OpenSSL < 1.0.0e due to issues with
 * thread-safety and security in server mode ephemereal ECDH cipher suites.
 * http://www.openssl.org/news/secadv_20110906.txt
 */
#if (OPENSSL_VERSION_NUMBER < 0x10000000L) && !defined(OPENSSL_NO_THREADID)
#define OPENSSL_NO_THREADID
#endif
#if (OPENSSL_VERSION_NUMBER < 0x0090806FL) && !defined(OPENSSL_NO_TLSEXT)
#define OPENSSL_NO_TLSEXT
#endif
#if (OPENSSL_VERSION_NUMBER < 0x1000005FL) && !defined(OPENSSL_NO_ECDH)
#define OPENSSL_NO_ECDH
#endif
#if (OPENSSL_VERSION_NUMBER < 0x0090802FL) && !defined(OPENSSL_NO_ECDSA)
#define OPENSSL_NO_ECDSA
#endif
#if (OPENSSL_VERSION_NUMBER < 0x0090802FL) && !defined(OPENSSL_NO_EC)
#define OPENSSL_NO_EC
#endif

/*
 * Workaround for bug in OpenSSL 1.0.0k and 1.0.1e
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=703031
 * http://openssl.6102.n7.nabble.com/NULL-ptr-deref-when-calling-SSL-get-certificate-with-1-0-0k-td43636.html
 */
#if (OPENSSL_VERSION_NUMBER == 0x100000bfL) || \
    (OPENSSL_VERSION_NUMBER == 0x1000105fL)
#define SSL_get_certificate(x) ssl_ssl_cert_get(x)
X509 * ssl_ssl_cert_get(SSL *);
#endif /* OpenSSL 1.0.0k or 1.0.1e */

void ssl_openssl_version(void);
int ssl_init(void) WUNRES;
void ssl_reinit(void);
void ssl_fini(void);

char * ssl_ssl_state_to_str(SSL *) NONNULL(1) MALLOC;

#ifndef OPENSSL_NO_DH
DH * ssl_tmp_dh_callback(SSL *, int, int) NONNULL(1) MALLOC;
DH * ssl_dh_load(const char *) NONNULL(1) MALLOC;
void ssl_dh_refcount_inc(DH *) NONNULL(1);
#endif /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC
#define SSL_EC_KEY_CURVE_DEFAULT "secp160r2"
EC_KEY * ssl_ec_by_name(const char *) MALLOC;
#endif /* !OPENSSL_NO_EC */

EVP_PKEY * ssl_key_load(const char *) NONNULL(1) MALLOC;
EVP_PKEY * ssl_key_genrsa(const int) MALLOC;
void ssl_key_refcount_inc(EVP_PKEY *) NONNULL(1);

#ifndef OPENSSL_NO_TLSEXT
int ssl_x509_v3ext_add(X509V3_CTX *, X509 *, char *, char *) NONNULL(1,2,3,4);
int ssl_x509_v3ext_copy_by_nid(X509 *, X509 *, int) NONNULL(1,2);
#endif /* !OPENSSL_NO_TLSEXT */
int ssl_x509_serial_copyrand(X509 *, X509 *) NONNULL(1,2);
X509 * ssl_x509_forge(X509 *, EVP_PKEY *, X509 *, const char *, EVP_PKEY *)
       NONNULL(1,2,3,5) MALLOC;
X509 * ssl_x509_load(const char *) NONNULL(1) MALLOC;
char * ssl_x509_subject(X509 *) NONNULL(1) MALLOC;
char * ssl_x509_subject_cn(X509 *, size_t *) NONNULL(1,2) MALLOC;
#define SSL_X509_FPRSZ 20
int ssl_x509_fingerprint_sha1(X509 *, unsigned char *) NONNULL(1,2);
char ** ssl_x509_names(X509 *) NONNULL(1) MALLOC;
int ssl_x509_names_match(X509 *, const char *) NONNULL(1,2);
char * ssl_x509_names_to_str(X509 *) NONNULL(1) MALLOC;
char ** ssl_x509_aias(X509 *, const int) NONNULL(1) MALLOC;
char ** ssl_x509_ocsps(X509 *) NONNULL(1) MALLOC;
int ssl_x509_is_valid(X509 *) NONNULL(1) WUNRES;
char * ssl_x509_to_str(X509 *) NONNULL(1) MALLOC;
char * ssl_x509_to_pem(X509 *) NONNULL(1) MALLOC;
void ssl_x509_refcount_inc(X509 *) NONNULL(1);

int ssl_x509chain_load(X509 **, STACK_OF(X509) **, const char *) NONNULL(2,3);
void ssl_x509chain_use(SSL_CTX *, X509 *, STACK_OF(X509) *) NONNULL(1,2,3);

char * ssl_session_to_str(SSL_SESSION *) NONNULL(1) MALLOC;
int ssl_session_is_valid(SSL_SESSION *) NONNULL(1);

int ssl_is_ocspreq(const unsigned char *, size_t) NONNULL(1) WUNRES;

#ifndef OPENSSL_NO_TLSEXT
char * ssl_tls_clienthello_parse_sni(const unsigned char *, ssize_t *)
       NONNULL(1,2) MALLOC;
#endif /* !OPENSSL_NO_TLSEXT */
int ssl_dnsname_match(const char *, size_t, const char *, size_t)
    NONNULL(1,3) WUNRES;
char * ssl_wildcardify(const char *) NONNULL(1) MALLOC;

#endif /* !SSL_H */

/* vim: set noet ft=c: */
