#include "main.h"

bool operationMode;
char configFilePath[STRING_SIZE];
struct Config config;
Options options;

void parse_cmd_line(int argc, char *argv[]) {
	char ch;

	operationMode = BACKGROUND_MODE;
	configFilePath[0] = '\0';

	for(int i=1; i<argc; i++) {
		if(argv[i][0] == '-') {
			ch = argv[i][1];

			switch(ch) {
				case 'd':
					operationMode = FORGROUND_MODE;
					break;
				case 'c':
					memset(configFilePath, 0, sizeof(configFilePath));
					strcpy(configFilePath, argv[i+1]);
					i++;
					break;
				default:
					log_message(WARNING_LOG, "Unknown option.");
					break;
			}
		}
	}
}

int initialize() {
	int ret;

	if (cachemgr_preinit() == -1) {
		log_message(ERROR_LOG, "failed to preinit cachemgr.");
		return 1;
	}

	if (log_preinit() == -1) {
		log_message(ERROR_LOG, "failed to preinit logging.");
		return 1;
	}

	if(operationMode == BACKGROUND_MODE) {
		ret = go_daemon();
		if(ret ) {
			return 1;
		}
	}

	if (cachemgr_init() == -1) {
		log_message(ERROR_LOG, "Failed to init cache manager.");
		return 1;
	}

	if (log_init() == -1) {
		log_message(ERROR_LOG, "failed to init log facility.");
		return 1;
	}

	if (ssl_ctx_init() == 1) {
		log_message(ERROR_LOG, "failed to init ssl context.");
		return 1;
	}

	cachemgr_gc();

	return 0;
}

vector<string> split(string str, char delimiter) {
	vector<string> splited;
	stringstream ss(str);
	string tok;

	while(getline(ss, tok, delimiter)) {
		splited.push_back(tok);
	}

	return splited;
}

int load_config() {
	string tmp;
	vector<string> splited;
	int tmpSize, tmpPort;

	if(configFilePath[0] == '\0') {
		strcpy(configFilePath, DEFAULT_CONFIG_FILE_PATH);
	}

	if(!options.read_options_file(configFilePath)) {
		log_message(ERROR_LOG, "Couldn't read configuration file %s.", configFilePath);
		return 1;
	}

	tmp = options["logLevel"];
	config.logLevel = atoi(tmp.c_str());

	tmp = options["maxClients"];
	config.maxClients = atoi(tmp.c_str());

	config.logFilePath = options["logFilePath"];

	tmp = options["bindPort"];
	config.bindPort = atoi(tmp.c_str());

	tmp = options["sslPorts"];
	splited = split(tmp, ',');
	tmpSize = splited.size();
	for(int i=0; i<tmpSize; i++) {
		tmpPort = atoi(splited.at(i).c_str());
		if((tmpPort >= 0) && (tmpPort <= 65535)) {
			config.sslPorts.push_back(tmpPort);
		}
	}

	/* load certificate */
	tmp = options["cacrt"];
	config.cacrt = ssl_x509_load(tmp.c_str());
	if(!config.cacrt) {
		log_message(ERROR_LOG, "Could not loading ca crt %s.", tmp.c_str());
		return 1;
	}

	config.chain = sk_X509_new_null();
	ssl_x509_refcount_inc(config.cacrt);
	sk_X509_insert(config.chain, config.cacrt, 0);

	tmp = options["cakey"];
	config.cakey = ssl_key_load(tmp.c_str());
	if (!config.cakey) {
		log_message(ERROR_LOG, "Could not loading ca key %s.", tmp.c_str());
		return 1;
	}

	tmp = options["leafkey"];
	config.key = ssl_key_load(tmp.c_str());
	if (!config.key) {
		log_message(ERROR_LOG, "Could not loading leaf key %s.", tmp.c_str());
		return 1;
	}

	config.ciphers = strdup("ALL:-aNULL");
	if (!config.ciphers) {
		log_message(ERROR_LOG, "Could not malloc ciphers.");
		return 1;
	}

	tmp = options["contentLogDir"];
	config.contentLogDir = strdup(tmp.c_str());
	if (!config.contentLogDir) {
		log_message(ERROR_LOG, "Could not malloc contentLogDir.");
		return 1;
	}

	if (!sys_isdir(config.contentLogDir)) {
		log_message(ERROR_LOG, "%s is not a directory.", config.contentLogDir);
		return 1;
	}

	return 0;
}

bool write_pid_file(string pidFileName) {

	unlink(pidFileName.c_str());
	FILE *f = fopen(pidFileName.c_str(), "w+");
	if(!f)
		return false;

	fprintf(f, "%d\n", getpid());
	fclose(f);

	return true;
}

int go_daemon() {
	pid_t fs;
	FILE *f = NULL;
	int ret;
	struct stat st;
	char command[STRING_SIZE];
	char pid[STRING_SIZE];

	memset(command, 0, sizeof(command));
	memset(pid, 0, sizeof(pid));

	f = fopen(PID_FILE_PATH, "r");
	if(f) {
		ret = fread(pid, 1, sizeof(pid), f);
		pid[ret-1] = '\0';
		if(strlen(pid) != 0) {
			sprintf(command, "/proc/%s", pid);
			if(stat(command, &st) != -1) {
				log_message(WARNING_LOG, "The process is already running.");
				return 1;
			}
		}
	}

	fs = fork();
	if(fs > 0) {
		exit(0);
	}

	if(fs < 0) {
		log_message(ERROR_LOG, "fork fail.");
		return 1;
	}

	if(!write_pid_file(PID_FILE_PATH)) {
		log_message(ERROR_LOG, "Couldn't write PID file.\n");
		return 1;
	}

	return 0;
}

/*
 * Returns 1 if path points to an existing directory node in the filesystem.
 * Returns 0 if path is NULL, does not exist, or points to a file of some kind.
 */
int sys_isdir(const char *path) {
	struct stat s;

	if (stat(path, &s) == -1)
		return 0;
	if (s.st_mode & S_IFDIR)
		return 1;
	return 0;
}

int ssl_ctx_init() {
	config.dstsslctx = SSL_CTX_new(SSLv23_method());
	if (!config.dstsslctx) {
		return 1;
	}

	SSL_CTX_set_options(config.dstsslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(config.dstsslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(config.dstsslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(config.dstsslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(config.dstsslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef DISABLE_SSLV2_CLIENT
	SSL_CTX_set_options(config.dstsslctx, SSL_OP_NO_SSLv2);
#endif /* DISABLE_SSLV2_CLIENT */
	SSL_CTX_set_verify(config.dstsslctx, SSL_VERIFY_NONE, NULL);

	return 0;
}

/*
 * Converts an IPv4/IPv6 sockaddr into a printable string representation.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
char* sys_sockaddr_str(struct sockaddr *addr, socklen_t addrlen)
{
	char host[INET6_ADDRSTRLEN], serv[6];
	char *buf;
	int rv;
	size_t bufsz;

	bufsz = sizeof(host) + sizeof(serv) + 3;
	buf = (char*)malloc(bufsz);
	if (!buf) {
		log_message(ERROR_LOG, "Cannot allocate memory.");
		return NULL;
	}
	rv = getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
	                 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rv != 0) {
		log_message(ERROR_LOG, "Cannot get nameinfo for socket address: %s.", gai_strerror(rv));
		free(buf);
		return NULL;
	}
	snprintf(buf, bufsz, "[%s]:%s", host, serv);
	return buf;
}


void config_free() {
	sk_X509_pop_free(config.chain, X509_free);
	if (config.cacrt) {
		X509_free(config.cacrt);
	}
	if (config.cakey) {
		EVP_PKEY_free(config.cakey);
	}
	if (config.key) {
		EVP_PKEY_free(config.key);
	}
#ifndef OPENSSL_NO_DH
	if (config.dh) {
		DH_free(config.dh);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (config.ecdhcurve) {
		free(config.ecdhcurve);
	}
#endif /* !OPENSSL_NO_ECDH */
	if (config.ciphers) {
		free(config.ciphers);
	}
	if (config.dropuser) {
		free(config.dropuser);
	}
	if (config.dropgroup) {
		free(config.dropgroup);
	}
	if (config.contentLogDir) {
		free(config.contentLogDir);
	}

	if (config.dstsslctx) {
		SSL_CTX_free(config.dstsslctx);
	}
}

int main(int argc, char *argv[]) {
	int ret;

	config.logFilePath = DEFAULT_LOG_FILE_PATH;
	config.logLevel = INFO_LOG;

	parse_cmd_line(argc, argv);

	ret = load_config();
	if(ret) {
		log_message(ERROR_LOG, "Loading configuration failed.");
		config_free();
		return 1;
	}

	ret = initialize();
	if(ret != 0) {
		log_message(ERROR_LOG, "initialize is failed.");
		config_free();
		return 1;
	}

	ret = socks_proxy();

	cachemgr_fini();
	log_fini();
	config_free();

	return 0;
}



