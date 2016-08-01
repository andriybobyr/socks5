#ifndef LOG_H
#define LOG_H

#include "main.h"
#include "thrqueue.h"

#include <syslog.h>
#include <stdarg.h>

/* log level */
#define INFO_LOG	0
#define WARNING_LOG	1
#define ERROR_LOG	2

#define DEFAULT_LOG_FILE_PATH "/var/log/socks5.log"

typedef struct log_content_ctx {
	int open;
	char *basedir;
	int fd;
	char *header_in;
	char *header_out;
	char *path;
	int size;
} log_content_ctx_t;

typedef struct logbuf {
	unsigned char *buf;
	ssize_t sz;
	int fd;
	struct logbuf *next;
} logbuf_t;

typedef ssize_t (*logger_write_func_t)(int, const void *, size_t);
typedef struct thrqueue thrqueue_t;

typedef struct logger {
	pthread_t thr;
	logger_write_func_t write;
	thrqueue_t *queue;
} logger_t;


void log_content_open(log_content_ctx_t *, char *, int, char *, int, char *);
void log_content_submit(log_content_ctx_t *, logbuf_t *, int);
void log_content_close(log_content_ctx_t *);
int log_preinit();
int log_init();
void log_fini();


typedef ssize_t (*writefunc_t)(int, const void *, size_t);
logbuf_t * logbuf_new(void *, size_t, int, logbuf_t *);
logbuf_t * logbuf_new_alloc(size_t, int, logbuf_t *);
logbuf_t * logbuf_new_copy(const void *, size_t, int, logbuf_t *);
logbuf_t * logbuf_new_printf(int, logbuf_t *, const char *, ...);
ssize_t logbuf_size(logbuf_t *);
ssize_t logbuf_write_free(logbuf_t *, writefunc_t);
void logbuf_free(logbuf_t *);


logger_t * logger_new(logger_write_func_t);
void logger_free(logger_t *);
int logger_start(logger_t *);
void logger_leave(logger_t *);
int logger_join(logger_t *);
int logger_stop(logger_t *);
int logger_submit(logger_t *, logbuf_t *);
int logger_printf(logger_t *, int, const char *, ...);
int logger_print(logger_t *, int, const char *);
int logger_write(logger_t *, int, const void *, size_t);
int logger_print_freebuf(logger_t *, int, char *);
int logger_write_freebuf(logger_t *, int, void *, size_t);


void log_message(int level, const char *format, ...);

#endif

