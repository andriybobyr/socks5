#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#include <pthread.h>

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <algorithm>
#include <set>
#include <vector>
#include <map>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

//#include <event2/event.h>

#include "log.h"
#include "options.h"
#include "socks5.h"
#include "attrib.h"
#include "cert.h"
#include "dynbuf.h"
#include "khash.h"
#include "pxyssl.h"
#include "ssl.h"

#ifndef SERVER_PORT_MAX_COUNT
#define SERVER_PORT_MAX_COUNT 256
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 5555
#endif

#define MAXPENDING 512
#define BUF_SIZE 65536
#define STRING_SIZE 1024

/* Operation mode*/
#define BACKGROUND_MODE 0
#define FORGROUND_MODE 1

/* default configuration file path*/
#define DEFAULT_CONFIG_FILE_PATH "/etc/socks5/socks5.conf"
#define PID_FILE_PATH "/var/run/socks5.pid"


using namespace std;

struct Config {
	int logLevel;
	int bindPort;
	vector<int> sslPorts;
	int maxClients;
	string logFilePath;

	char *dropuser;
	char *dropgroup;
	char *contentLogDir;

	SSL_CTX *dstsslctx;

	char *ciphers;
	X509 *cacrt;
	EVP_PKEY *cakey;
	EVP_PKEY *key;
	STACK_OF(X509) *chain;
#ifndef OPENSSL_NO_DH
	DH *dh;
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	char *ecdhcurve;
#endif /* !OPENSSL_NO_ECDH */
};


extern struct Config config;
extern bool operationMode;
extern char configFilePath[STRING_SIZE];

void parse_cmd_line(int argc, char *argv[]);
int initialize();
int load_config();
int go_daemon();
void config_free();
bool write_pid_file(string pidFileName);
vector<string> split(string str, char delimiter);
int sys_isdir(const char *path);
char* sys_sockaddr_str(struct sockaddr *addr, socklen_t addrlen);
int ssl_ctx_init();

#endif

