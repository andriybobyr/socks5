#include "socks5.h"


Lock getHostLock;
Event clientLock;
int clientCount = 0;


void sig_handler(int signum) {

}

int create_listen_socket() {
	int serverSock;
	struct sockaddr_in echoServer;

	/* Create the TCP socket */
	if((serverSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_message(ERROR_LOG, "Could not create socket.");
		return -1;
	}

	/* Construct the server sockaddr_in structure */
	memset(&echoServer, 0, sizeof(echoServer));
	echoServer.sin_family = AF_INET;
	echoServer.sin_addr.s_addr = htonl(INADDR_ANY);
	echoServer.sin_port = htons(config.bindPort);

	/* Bind the server socket */
	if(bind(serverSock, (struct sockaddr *)&echoServer, sizeof(echoServer)) < 0) {
		log_message(ERROR_LOG, "Bind error.");
		return -1;
	}

	/* Listen on the server socket */
	if(listen(serverSock, MAXPENDING) < 0) {
		log_message(ERROR_LOG, "Bind error.");
		return -1;
	}

	return serverSock;
}

int receive_sock(int sock, char *buffer, uint32_t size) {
	int index = 0, ret;

	while(size) {
		if((ret = recv(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}

	return index;
}

int send_sock(int sock, const char *buffer, uint32_t size)
{
	int index = 0, ret;

	while(size) {
		if((ret = send(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}

	return index;
}

string int_to_str(uint32_t ip) {
	ostringstream oss;

	for(unsigned i=0; i<4; i++) {
		oss << ((ip >> (i*8)) & 0xff);
		if(i != 3)
			oss << '.';
	}

	return oss.str();
}

int connect_to_host(uint32_t ip, uint16_t port) {
	struct sockaddr_in serverAddr;
	struct hostent *server;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
		return -1;

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	string ipString = int_to_str(ip);

	getHostLock.lock();
	server = gethostbyname(ipString.c_str());
	if(!server) {
		getHostLock.unlock();
		return -1;
	}
	memcpy((char *)&serverAddr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
	getHostLock.unlock();

	serverAddr.sin_port = htons(port);
	return !connect(sockfd, (const sockaddr*)&serverAddr, sizeof(serverAddr)) ? sockfd : -1;
}

int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz) {
	if((receive_sock(sock, (char*)buffer, 1) != 1) || (buffer[0] > max_sz))
		return false;
	uint8_t sz = buffer[0];
	if(receive_sock(sock, (char*)buffer, sz) != sz)
		return -1;
	return sz;
}

bool handle_handshake(void *arg, char *buffer) {
	struct socketInfo *client = (struct socketInfo*)arg;
	int sock = client->fd;
	MethodIdentificationPacket packet;
	int readSize = receive_sock(sock, (char*)&packet, sizeof(MethodIdentificationPacket));

	if(readSize != sizeof(MethodIdentificationPacket) || packet.version != 5) {
		log_message(INFO_LOG, "handle_handshake : readSize = %d, packet.version = %d", readSize, packet.version);
		log_message(ERROR_LOG, "handle_handshake : The readSize and the version of packet are mistakes.");
		return false;
	}

	if(receive_sock(sock, buffer, packet.nmethods) != packet.nmethods) {
		log_message(ERROR_LOG, "ERROR : handle_handshake : receve_sock fail.");
		return false;
	}

	MethodSelectionPacket response(METHOD_NOTAVAILABLE);

	for(int i=0; i< packet.nmethods; i++) {
		if(buffer[i] == METHOD_NOAUTH)
		{
			response.method = METHOD_NOAUTH;
		}
		/*if(buffer[i] == METHOD_AUTH)
			response.method = METHOD_AUTH;*/
	}

	if(send_sock(sock, (const char*)&response, sizeof(MethodSelectionPacket)) != sizeof(MethodSelectionPacket) || response.method == METHOD_NOTAVAILABLE) {
		return false;
	}

	return true;
}

void set_fds(int sock1, int sock2, fd_set *fds) {
	FD_ZERO(fds);
	FD_SET(sock1, fds);
	FD_SET(sock2, fds);
}

void do_proxy(int realServerSock, int clientSock, char *buffer) {
	fd_set readfds;
	int result, recvd, nfds = max(realServerSock, clientSock)+1;

	set_fds(realServerSock, clientSock, &readfds);

	while((result = select(nfds, &readfds, 0, 0, 0)) > 0) {
		if(FD_ISSET(realServerSock, &readfds)) {
			recvd = recv(realServerSock, buffer, BUF_SIZE-1, 0);
			if(recvd <= 0)
				return;
			send_sock(clientSock, buffer, recvd);
		}

		if(FD_ISSET(clientSock, &readfds)) {
			recvd = recv(clientSock, buffer, BUF_SIZE-1, 0);
			if(recvd <= 0)
				return;
			send_sock(realServerSock, buffer, recvd);
		}
		set_fds(realServerSock, clientSock, &readfds);
	}
}

bool handle_request(void *arg, char *buffer) {
	struct socketInfo *client = (struct socketInfo*)arg;
	int sock = client->fd;
	SOCKS5RequestHeader header;
	vector<int>::iterator it;
	bool isSsl = false;
	SOCKS5IP4RequestBody req;
	SOCKS5DNameRequestBody dnReq;
	struct hostent *phost;
	uint32_t ip;
	uint16_t port;

	receive_sock(sock, (char*)&header, sizeof(SOCKS5RequestHeader));
	if ((header.version !=5) || (header.cmd != CMD_CONNECT) || (header.rsv != 0)) {
		return false;
	}
	int realServerSock = -1;

	switch(header.atyp) {
		case ATYP_IPV4:
		{
			if (receive_sock(sock, (char*)&req, sizeof(SOCKS5IP4RequestBody)) != sizeof(SOCKS5IP4RequestBody)) {
				return false;
			}

			for(it=config.sslPorts.begin(); it!=config.sslPorts.end(); ++it) {
				if(ntohs(req.port) == *it) {
					isSsl = true;
					break;
				}
			}

			realServerSock = connect_to_host(req.ip_dst, ntohs(req.port));
			ip = req.ip_dst;
			port = req.port;
			break;
		}
		case ATYP_DNAME:
		{
			memset(&dnReq, 0, sizeof(SOCKS5DNameRequestBody));
			if (receive_sock(sock, (char*)&dnReq, sizeof(SOCKS5DNameRequestBody)) != sizeof(SOCKS5DNameRequestBody)) {
				return false;
			}

			if (receive_sock(sock, buffer, dnReq.length+2) != dnReq.length+2) {
				return false;
			}

			memcpy(&port, buffer+dnReq.length, 2);
			buffer[dnReq.length] = 0;
			buffer[dnReq.length+1] = 0;

			//log_message(INFO_LOG, "dns = %s, port = %d", buffer, ntohs(port));

			phost = gethostbyname(buffer);
			if (!phost) {
				log_message(ERROR_LOG, "Could not resolve host name");
				return false;
			}

			memcpy(&ip, phost->h_addr, phost->h_length);

			for(it=config.sslPorts.begin(); it!=config.sslPorts.end(); ++it) {
				if(ntohs(port) == *it) {
					isSsl = true;
					break;
				}
			}

			realServerSock = connect_to_host(ip, ntohs(port));
			break;
		}
		default:
			return false;
	}

	if (realServerSock == -1) {
		return false;
	}

	SOCKS5Response response;
	response.ip_src = 0;
	response.port_src = config.bindPort;
	send_sock(sock, (const char*)&response, sizeof(SOCKS5Response));

	if (isSsl) {
		do_ssl_proxy(realServerSock, sock, ip, ntohs(port), arg);
	} else {
		do_proxy(realServerSock, sock, buffer);
	}

	shutdown(realServerSock, SHUT_RDWR);
	close(realServerSock);
	return true;
}

void *handle_connection(void *arg) {
	struct socketInfo *client = (struct socketInfo *)arg;
	int sock = client->fd;
	char *buffer = new char[BUF_SIZE];
	if(handle_handshake(arg, buffer))
		handle_request(arg, buffer);
	else
		log_message(ERROR_LOG, "handle_handshake is failed.");
	shutdown(sock, SHUT_RDWR);
	close(sock);
	delete[] buffer;
	free(client);
	clientLock.lock();
	clientCount--;
	if(clientCount == (config.maxClients - 1))
		clientLock.signal();
	clientLock.unlock();
	return 0;
}

bool spawn_thread(pthread_t *thread, void *data) {
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 * 1024);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	return !pthread_create(thread, &attr, handle_connection, data);
}

int socks_proxy() {
	struct socketInfo *client;
	struct sockaddr_in echoClient;
	int clientSock;
	int listenSock = create_listen_socket();

	if(listenSock == -1) {
		log_message(ERROR_LOG, "[-] Failed to create server.");
		return 1;
	}

	signal(SIGPIPE, sig_handler);
	while(true) {
		uint32_t clientLen = sizeof(echoClient);
		
		clientLock.lock();
		if(clientCount == config.maxClients)
			clientLock.wait();
		clientLock.unlock();

		if((clientSock = accept(listenSock, (struct sockaddr*)&echoClient, &clientLen)) > 0) {
			clientLock.lock();
			clientCount++;
			clientLock.unlock();
			pthread_t thread;

			client = (struct socketInfo*)malloc(sizeof(struct socketInfo));
			client->fd = clientSock;
			client->addr.sin_addr.s_addr = echoClient.sin_addr.s_addr;
			client->addr.sin_port = echoClient.sin_port;
			spawn_thread(&thread, (void*)client);
		}
	}
}














