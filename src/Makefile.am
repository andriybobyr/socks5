## $Id: Makefile.am,v 1.11 2015/07/18 00:35:19 takesi Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies
bin_PROGRAMS = socks5
socks5_SOURCES = main.cpp main.h options.cpp options.h \
		log.cpp log.h socks5.cpp socks5.h \
		ssl.cpp ssl.h attrib.h khash.h \
		cert.cpp cert.h cache.cpp cache.h \
		cachefkcrt.cpp cachefkcrt.h pxyssl.cpp pxyssl.h \
		cachetgcrt.cpp cachetgcrt.h cachessess.cpp cachessess.h \
		dynbuf.cpp dynbuf.h cachedsess.cpp cachedsess.h \
		cachemgr.cpp cachemgr.h thrqueue.cpp thrqueue.h

socks5_LDADD = -lpthread -lssl -lcrypto
SUBDIRS =
INCLUDES = -I$(top_srcdir) @extra_incl@
