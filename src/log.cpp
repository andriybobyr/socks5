#include "log.h"

logger_t *content_log = NULL;
static int content_fd = -1; /* if set, we are in single file mode */
static const char *content_basedir = NULL;

void log_message(int level, const char *format, ...) {
	if(config.logLevel > level) return;

	FILE *f;
	char buf[STRING_SIZE+1];
	va_list ap;

	memset(buf, '\0', sizeof(buf));
	va_start(ap, format);
	vsnprintf(buf, STRING_SIZE, format, ap);

	if(operationMode == FORGROUND_MODE) {
		switch(level) {
			case INFO_LOG:
				printf("INFO : %s\n", buf);
				break;
			case WARNING_LOG:
				printf("WARNING : %s\n", buf);
				break;
			case ERROR_LOG:
				printf("ERROR : %s\n", buf);
				break;
			default:
				break;
		}
	} else {
		f = fopen(config.logFilePath.c_str(), "a+");

		switch(level) {
			case INFO_LOG:
				fprintf(f, "INFO : %s\n", buf);
				break;
			case WARNING_LOG:
				fprintf(f, "WARNING : %s\n", buf);
				break;
			case ERROR_LOG:
				fprintf(f, "ERROR : %s\n", buf);
				break;
			default:
				break;
		}

		fclose(f);
	}

	va_end(ap);
}

static int log_content_open_logdir(const char *basedir)
{
	content_basedir = basedir;
	return 0;
}

static void log_content_close_singlefile(void)
{
	if (content_fd != -1) {
		close(content_fd);
		content_fd = -1;
	}
}

void log_content_open(log_content_ctx_t *ctx, char *srcaddr, int srcport, char *dstaddr, int dstport, char *servername)
{
	char filename[1024];
	char timebuf[24];
	time_t epoch;
	struct tm *utc;

	int ret = 1;
	if (ctx->open)
		return;

	if (content_fd != -1) {
		ctx->fd = content_fd;
		ret = asprintf(&ctx->header_in, "%s -> %s", srcaddr, dstaddr);
		ret = asprintf(&ctx->header_out, "%s -> %s", dstaddr, srcaddr);
	} else {
		time(&epoch);
		utc = gmtime(&epoch);
		strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", utc);
		snprintf(filename, sizeof(filename), "%s/%s-%s-%d-%s-%d.log",
		         content_basedir, timebuf, srcaddr, srcport, servername, dstport);
		ctx->fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, 0660);
		if (ctx->fd == -1) {
			log_message(ERROR_LOG, "Failed to open '%s': %s\n", filename, strerror(errno));
		}
	}
	ret = 1;
	ctx->open = ret;

	ctx->size = 0;
	ctx->path = strdup(filename);
}

void log_content_submit(log_content_ctx_t *ctx, logbuf_t *lb, int direction)
{
	logbuf_t *head;
	time_t epoch;
	struct tm *utc;
	char *header;

	if (!ctx->open) {
		log_message(ERROR_LOG, "log_content_submit called on closed ctx.");
		return;
	}

	if (!(header = direction ? ctx->header_out : ctx->header_in))
		goto out;

	/* prepend size tag and newline */
	head = logbuf_new_printf(lb->fd, lb, " (%zu):\n", logbuf_size(lb));
	if (!head) {
		log_message(ERROR_LOG, "Failed to allocate memory.");
		logbuf_free(lb);
		return;
	}
	lb = head;

	/* prepend header */
	head = logbuf_new_copy(header, strlen(header), lb->fd, lb);
	if (!head) {
		log_message(ERROR_LOG, "Failed to allocate memory.");
		logbuf_free(lb);
		return;
	}
	lb = head;

	/* prepend timestamp */
	head = logbuf_new_alloc(32, lb->fd, lb);
	if (!head) {
		log_message(ERROR_LOG, "Failed to allocate memory.");
		logbuf_free(lb);
		return;
	}
	lb = head;
	time(&epoch);
	utc = gmtime(&epoch);
	lb->sz = strftime((char*)lb->buf, lb->sz, "%Y-%m-%d %H:%M:%S UTC ",
	                  utc);

out:
	lb->fd = ctx->fd;
	ctx->size += lb->sz;
	logger_submit(content_log, lb);
}

void log_content_close(log_content_ctx_t *ctx)
{
	if (!ctx->open)
		return;
	if (content_fd == -1) {
		logger_write_freebuf(content_log, ctx->fd, NULL, 0);
	}
	if (ctx->header_in) {
		free(ctx->header_in);
	}
	if (ctx->header_out) {
		free(ctx->header_out);
	}

	if (ctx->size == 0) {
		unlink(ctx->path);
	}

	if (ctx->path) {
		free(ctx->path);
	}

	ctx->open = 0;
}

/*
 * Do the actual write to the open connection log file descriptor.
 * We prepend a timestamp here, which means that timestamps are slightly
 * delayed from the time of actual logging.  Since we only have second
 * resolution that should not make any difference.
 */
static ssize_t log_content_writecb(int fd, const void *buf, size_t sz)
{
	if (!buf) {
		close(fd);
		return 0;
	}

	if (write(fd, buf, sz) == -1) {
		log_message(WARNING_LOG, "Warning: Failed to write to content log: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Initialization and destruction.
 */

/*
 * Log pre-init: open all log files but don't start any threads, since we may
 * fork() after pre-initialization.
 * Return -1 on errors, 0 otherwise.
 */
int log_preinit()
{
	if (config.contentLogDir) {
		if (log_content_open_logdir(config.contentLogDir) == -1) {
				goto out;
		}

		if (!(content_log = logger_new(log_content_writecb))) {
			log_content_close_singlefile();
			goto out;
		}
	}

	return 0;

out:
	if (content_log) {
		log_content_close_singlefile();
		logger_free(content_log);
	}
	return -1;
}

/*
 * Log post-init: start logging threads.
 * Return -1 on errors, 0 otherwise.
 */
int log_init()
{
	if (content_log)
		if (logger_start(content_log) == -1)
			return -1;
	return 0;
}

/*
 * Drain and cleanup.  Tell all loggers to leave, then join all logger threads,
 * and finally free resources and close log files.
 */
void log_fini(void)
{
	if (content_log)
		logger_leave(content_log);

	if (content_log)
		logger_join(content_log);

	if (content_log)
		logger_free(content_log);

	if (content_log)
		log_content_close_singlefile();
}

/*
 * Dynamic log buffer with zero-copy chaining and fd meta information.
 * Logbuf always owns the internal allocated buffer.
 */

/*
 * Create new logbuf from provided, pre-allocated buffer, set fd and next.
 * The provided buffer will be freed by logbuf_free() if non-NULL.
 */
logbuf_t * logbuf_new(void *buf, size_t sz, int fd, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = (logbuf_t*)malloc(sizeof(logbuf_t))))
		return NULL;
	lb->buf = (unsigned char*)buf;
	lb->sz = sz;
	lb->fd = fd;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf, allocating sz bytes into the internal buffer.
 */
logbuf_t * logbuf_new_alloc(size_t sz, int fd, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = (logbuf_t*)malloc(sizeof(logbuf_t))))
		return NULL;
	if (!(lb->buf = (unsigned char*)malloc(sz))) {
		free(lb);
		return NULL;
	}
	lb->sz = sz;
	lb->fd = fd;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf, copying buf into a newly allocated internal buffer.
 */
logbuf_t * logbuf_new_copy(const void *buf, size_t sz, int fd, logbuf_t *next)
{
	logbuf_t *lb;

	if (!(lb = (logbuf_t*)malloc(sizeof(logbuf_t))))
		return NULL;
	if (!(lb->buf = (unsigned char*)malloc(sz))) {
		free(lb);
		return NULL;
	}
	memcpy(lb->buf, buf, sz);
	lb->sz = sz;
	lb->fd = fd;
	lb->next = next;
	return lb;
}

/*
 * Create new logbuf using printf, setting fd and next.
 */
logbuf_t * logbuf_new_printf(int fd, logbuf_t *next, const char *fmt, ...)
{
	va_list ap;
	logbuf_t *lb;

	if (!(lb = (logbuf_t*)malloc(sizeof(logbuf_t))))
		return NULL;
	va_start(ap, fmt);
	lb->sz = vasprintf((char**)&lb->buf, fmt, ap);
	va_end(ap);
	if (lb->sz == -1) {
		free(lb);
		return NULL;
	}
	lb->fd = fd;
	lb->next = next;
	return lb;
}

/*
 * Calculate the total size of the logbuf and all chained buffers.
 */
ssize_t logbuf_size(logbuf_t *lb)
{
	ssize_t sz;

	sz = lb->sz;
	if (lb->next) {
		sz += logbuf_size(lb->next);
	}
	return sz;
}

/*
 * Write content of logbuf using writefunc and free all buffers.
 * Returns -1 on errors and sets errno according to write().
 * Returns total of bytes written by 1 .. n write() calls on success.
 */
ssize_t logbuf_write_free(logbuf_t *lb, writefunc_t writefunc)
{
	ssize_t rv1, rv2 = 0;

	rv1 = writefunc(lb->fd, lb->buf, lb->sz);
	free(lb->buf);
	if (lb->next) {
		if (rv1 == -1) {
			logbuf_free(lb->next);
		} else {
			lb->next->fd = lb->fd;
			rv2 = logbuf_write_free(lb->next, writefunc);
		}
	}
	free(lb);
	if (rv1 == -1 || rv2 == -1)
		return -1;
	else
		return rv1 + rv2;
}

/*
 * Free dynbuf including internal and chained buffers.
 */
void logbuf_free(logbuf_t *lb)
{
	if (lb->buf) {
		free(lb->buf);
	}
	if (lb->next) {
		logbuf_free(lb->next);
	}
	free(lb);
}

static void logger_clear(logger_t *logger)
{
	memset(logger, 0, sizeof(logger_t));
}

/*
 * Create new logger with a specific write function callback.
 * The callback will be executed in the logger's writer thread,
 * not in the thread calling logger_submit().
 */
logger_t *
logger_new(logger_write_func_t writefunc)
{
	logger_t *logger;

	logger = (logger_t*)malloc(sizeof(logger_t));
	if (!logger)
		return NULL;
	logger_clear(logger);
	logger->write = writefunc;
	logger->queue = NULL;
	return logger;
}

/*
 * Free the logger data structures.  Caller must call logger_stop()
 * or logger_leave() and logger_join() prior to freeing.
 */
void
logger_free(logger_t *logger) {
	if (logger->queue) {
		thrqueue_free(logger->queue);
	}
	free(logger);
}

/*
 * Submit a buffer to be logged by the logger thread.
 * Buffer will be freed after logging completes.
 * Returns -1 on error, 0 on success.
 */
int
logger_submit(logger_t *logger, logbuf_t *lb)
{
	return thrqueue_enqueue(logger->queue, lb) ? 0 : -1;
}

/*
 * Logger thread main function.
 */
static void *
logger_thread(void *arg)
{
	logger_t *logger = (logger_t*)arg;
	logbuf_t *lb;

	while ((lb = (logbuf_t*)thrqueue_dequeue(logger->queue))) {
		logbuf_write_free(lb, logger->write);
	}

	return NULL;
}

/*
 * Start the logger's write thread.
 */
int
logger_start(logger_t *logger) {
	int rv;

	if (logger->queue) {
		thrqueue_free(logger->queue);
	}
	logger->queue = thrqueue_new(1024);

	rv = pthread_create(&logger->thr, NULL, logger_thread, logger);
	if (rv)
		return -1;
	sched_yield();
	return 0;
}

/*
 * Tell the logger's write thread to write all pending write requests
 * and then exit.  Don't wait for the logger to exit.
 */
void logger_leave(logger_t *logger) {
	thrqueue_unblock_dequeue(logger->queue);
	sched_yield();
}

/*
 * Wait for the logger to exit.
 */
int
logger_join(logger_t *logger) {
	int rv;

	rv = pthread_join(logger->thr, NULL);
	if (rv)
		return -1;
	return 0;
}

/*
 * Tell the logger's write thread to write all pending write requests
 * and then exit; wait for the logger to exit.
 */
int
logger_stop(logger_t *logger) {
	logger_leave(logger);
	return logger_join(logger);
}

/*
 * Generic print to a logger.  These functions should be called by the
 * actual worker thread(s) doing network I/O.
 *
 * _printf(), _print() and _write() copy the input buffers.
 * _ncprint() and _ncwrite() will free() the input buffers.
 *
 * The file descriptor argument is a virtual or real system file descriptor
 * used for multiplexing write requests to several files over the same
 * logger.  This argument is passed to the write handler as-is and is not
 * interpreted or used by the logger itself in any way.
 *
 * All of the functions return 0 on succes, -1 on failure.
 */
int
logger_printf(logger_t *logger, int fd, const char *fmt, ...)
{
	va_list ap;
	logbuf_t *lb;

	lb = logbuf_new(NULL, 0, fd, NULL);
	if (!lb)
		return -1;
	va_start(ap, fmt);
	lb->sz = vasprintf((char**)&lb->buf, fmt, ap);
	va_end(ap);
	if (lb->sz == -1) {
		logbuf_free(lb);
		return -1;
	}
	return logger_submit(logger, lb);
}
int
logger_write(logger_t *logger, int fd, const void *buf, size_t sz)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new_copy(buf, sz, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_print(logger_t *logger, int fd, const char *s)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new_copy(s, s ? strlen(s) : 0, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_write_freebuf(logger_t *logger, int fd, void *buf, size_t sz)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new(buf, sz, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}
int
logger_print_freebuf(logger_t *logger, int fd, char *s)
{
	logbuf_t *lb;

	if (!(lb = logbuf_new(s, s ? strlen(s) : 0, fd, NULL)))
		return -1;
	return logger_submit(logger, lb);
}


