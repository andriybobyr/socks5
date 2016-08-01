#ifndef PXYSSL_H
#define PXYSSL_H

#include "main.h"
#include "cachemgr.h"
#include "log.h"

void do_ssl_proxy(int realServerSock, int clientSock, uint32_t ip, uint16_t port, void *peer);

#endif/* !PXYSSL_H */