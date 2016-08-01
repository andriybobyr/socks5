#ifndef SOCKS5_H
#define SOCKS5_H

#include "main.h"

using namespace std;

/* Command constants */
#define CMD_CONNECT 		1
#define CMD_BIND 		2
#define CMD_UDP_ASSOCIATIVE	3

/* Address type constants */
#define ATYP_IPV4		1
#define ATYP_DNAME		3
#define ATYP_IPV6		4

/* Connection methods */
#define METHOD_NOAUTH		0
#define METHOD_AUTH		2
#define METHOD_NOTAVAILABLE	0Xff

/* Response */
#define RESP_SUCCEDED		0
#define RESP_GEN_ERROR		1

#define MAX_BODY_LEN 1024

/* Handshake */

struct MethodIdentificationPacket {
	uint8_t version, nmethods;
} __attribute__((packed));

struct MethodSelectionPacket {
	uint8_t version, method;
	MethodSelectionPacket(uint8_t met) : version(5), method(met) {}
} __attribute__((packed));

/* Requests */
struct SOCKS5RequestHeader {
	uint8_t version, cmd, rsv /* = 0x00 */, atyp;
} __attribute__((packed));

struct SOCKS5IP4RequestBody {
	uint32_t ip_dst;
	uint16_t port;
} __attribute__((packed));

struct SOCKS5DNameRequestBody {
	uint8_t length;
} __attribute__((packed));

/* Response */

struct SOCKS5Response {
	uint8_t version, cmd, rsv /* = 0x00 */, atyp;
	uint32_t ip_src;
	uint16_t port_src;

	SOCKS5Response(bool succeded = true) : version(5), cmd(succeded ? RESP_SUCCEDED : RESP_GEN_ERROR), rsv(0), atyp(ATYP_IPV4) {}
} __attribute__((packed));

struct socketInfo {
	struct sockaddr_in addr;
	int fd;
};

class Lock {
	pthread_mutex_t mutex;
    public:
	Lock() {
		pthread_mutex_init(&mutex, NULL);
	}

	~Lock() {
		pthread_mutex_destroy(&mutex);
	}

	inline void lock() {
		pthread_mutex_lock(&mutex);
	}

	inline void unlock() {
		pthread_mutex_unlock(&mutex);
	}
};

class Event {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
    public:
	Event() {
		pthread_mutex_init(&mutex, 0);
		pthread_cond_init(&condition, 0);
	}

	~Event() {
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&condition);
	}

	inline void lock() {
		pthread_mutex_lock(&mutex);
	}

	inline void unlock() {
		pthread_mutex_unlock(&mutex);
	}

	inline void signal() {
		pthread_cond_signal(&condition);
	}

	inline void broadcastSignal() {
		pthread_cond_broadcast(&condition);
	}

	inline void wait() {
		pthread_cond_wait(&condition, &mutex);
	}
};

void sig_handler(int signum);
int create_listen_socket();
int receive_sock(int sock, char *buffer, uint32_t size);
int send_sock(int sock, const char *buffer, uint32_t size);
string int_to_str(uint32_t ip);
int connect_to_host(uint32_t ip, uint16_t port);
int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz);
bool handle_handshake(void *arg, char *buffer);
void set_fds(int sock1, int sock2, fd_set *fds);
void do_proxy(int realServerSock, int clientSock, char *buffer);
bool handle_request(void *arg, char *buffer);
void *handle_connection(void *arg);
bool spawn_thread(pthread_t *thread, void *data);
int socks_proxy();

#endif









