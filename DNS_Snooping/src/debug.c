/*
 * debug/ARP Proxy / Debug prints
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "debug.h"
#include "dns_snooping.h"
#include <syslog.h>

#define MAX_LOG_SIZE 65535
static int dnss_debug_syslog = 0;

int dnss_debug_level = DNSS_INFO;
int dnss_debug_show_keys = 0;
int dnss_debug_timestamp = 1;
int dnss_debug_log_size = 0;

static FILE *out_file = NULL;

void dnss_debug_print_timestamp(void)
{
	struct os_time tv;

	if (!dnss_debug_timestamp)
		return;

	os_get_time(&tv);
	struct tm *time;
	time = localtime(&tv.sec);
	if (out_file) {
		fprintf(out_file, "[%d-%02d-%02d %02d:%02d:%02d]: ",(1900+time->tm_year),
		    (1+time->tm_mon),time->tm_mday,time->tm_hour,time->tm_min,time->tm_sec);
	} else
		printf("%d-%02d-%02d %02d:%02d:%02d: ",(1900+time->tm_year),(1+time->tm_mon),
	    time->tm_mday,time->tm_hour,time->tm_min,time->tm_sec);
}

#ifndef LOG_DNS
#define LOG_DNS LOG_DAEMON
#endif /* LOG_dnss */

void dnss_debug_open_syslog(void)
{
	openlog("DNS_SNooping", LOG_PID | LOG_NDELAY, LOG_DNS);
	dnss_debug_syslog++;
}


void dnss_debug_close_syslog(void)
{
	if (dnss_debug_syslog)
		closelog();
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
	case MSG_DEBUG:
		return LOG_DEBUG;
	case MSG_INFO:
		return LOG_NOTICE;
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_INFO;
}

const char * debug_level_str(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
		return "MSGDUMP";
	case MSG_DEBUG:
		return "DEBUG";
	case MSG_INFO:
		return "INFO";
	case MSG_WARNING:
		return "WARNING";
	case MSG_ERROR:
		return "ERROR";
	default:
		return "?";
	}
}


int str_to_debug_level(const char *s)
{
	if (os_strcasecmp(s, "MSGDUMP") == 0)
		return MSG_MSGDUMP;
	if (os_strcasecmp(s, "DEBUG") == 0)
		return MSG_DEBUG;
	if (os_strcasecmp(s, "INFO") == 0)
		return MSG_INFO;
	if (os_strcasecmp(s, "WARNING") == 0)
		return MSG_WARNING;
	if (os_strcasecmp(s, "ERROR") == 0)
		return MSG_ERROR;
	return -1;
}


/**
 * dnss_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void dnss_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (dnss_debug_log_size > MAX_LOG_SIZE) {
		dnss_debug_log_size = 0;
		dnss_debug_reopen_file();
	}

	if (level >= dnss_debug_level) {
		if (dnss_debug_syslog) {
			vsyslog(syslog_priority(level), fmt, ap);
		} else {
			dnss_debug_print_timestamp();
			if (out_file) {
				dnss_debug_log_size += vfprintf(out_file, fmt, ap);
				fflush(out_file);
				//fprintf(out_file, "\n");
			} else {
				dnss_debug_open_file(DNSS_OUT_FILE);
			}
		}
	}
	va_end(ap);
}


static void _dnss_hexdump(int level, const char *title, const u8 *buf,
			 size_t len, int show)
{
	size_t i;

	if (level < dnss_debug_level)
		return;

	if (dnss_debug_syslog) {
		const char *display;
		char *strbuf = NULL;

		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			strbuf = os_malloc(1 + 3 * len);
			if (strbuf == NULL) {
				dnss_printf(MSG_ERROR, "dnss_hexdump: Failed to "
					   "allocate message buffer\n");
				return;
			}

			for (i = 0; i < len; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		syslog(syslog_priority(level), "%s - hexdump(len=%lu):%s",
		       title, (unsigned long) len, display);
		os_free(strbuf);
		return;
	}

	dnss_debug_print_timestamp();

	if (out_file) {
		fprintf(out_file, "%s - hexdump(len=%lu):",
			title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(out_file, " [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				fprintf(out_file, " %02x", buf[i]);
		} else {
			fprintf(out_file, " [REMOVED]");
		}
		fprintf(out_file, "\n");
	} else {
		printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
		if (buf == NULL) {
			printf(" [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				printf(" %02x", buf[i]);
		} else {
			printf(" [REMOVED]");
		}
		printf("\n");
	}
}

void dnss_hexdump(int level, const char *title, const u8 *buf, size_t len)
{
	_dnss_hexdump(level, title, buf, len, 1);
}


void dnss_hexdump_key(int level, const char *title, const u8 *buf, size_t len)
{
	_dnss_hexdump(level, title, buf, len, dnss_debug_show_keys);
}


static void _dnss_hexdump_ascii(int level, const char *title, const u8 *buf,
			       size_t len, int show)
{
	size_t i, llen;
	const u8 *pos = buf;
	const size_t line_len = 16;

	if (level < dnss_debug_level)
		return;

	dnss_debug_print_timestamp();
	if (out_file) {
		if (!show) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			return;
		}
		fprintf(out_file, "%s - hexdump_ascii(len=%lu):\n",
			title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			fprintf(out_file, "    ");
			for (i = 0; i < llen; i++)
				fprintf(out_file, " %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				fprintf(out_file, "   ");
			fprintf(out_file, "   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					fprintf(out_file, "%c", pos[i]);
				else
					fprintf(out_file, "_");
			}
			for (i = llen; i < line_len; i++)
				fprintf(out_file, " ");
			fprintf(out_file, "\n");
			pos += llen;
			len -= llen;
		}
	} else {
		if (!show) {
			printf("%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			return;
		}
		printf("%s - hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			printf("    ");
			for (i = 0; i < llen; i++)
				printf(" %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				printf("   ");
			printf("   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					printf("%c", pos[i]);
				else
					printf("_");
			}
			for (i = llen; i < line_len; i++)
				printf(" ");
			printf("\n");
			pos += llen;
			len -= llen;
		}
	}
}


void dnss_hexdump_ascii(int level, const char *title, const u8 *buf, size_t len)
{
	_dnss_hexdump_ascii(level, title, buf, len, 1);
}


void dnss_hexdump_ascii_key(int level, const char *title, const u8 *buf,
			   size_t len)
{
	_dnss_hexdump_ascii(level, title, buf, len, dnss_debug_show_keys);
}

static char *last_path = NULL;

int dnss_debug_reopen_file(void)
{
	int rv;
	if (last_path) {
		char *tmp = os_strdup(last_path);
		dnss_debug_close_file();
		rv = dnss_debug_open_file(tmp);
		os_free(tmp);
	} else {
		dnss_printf(MSG_ERROR, "Last-path was not set, cannot "
			   "re-open log file.\n");
		rv = -1;
	}
	return rv;
}


int dnss_debug_open_file(const char *path)
{
	if (!path)
		return 0;

	if (last_path == NULL || os_strcmp(last_path, path) != 0) {
		/* Save our path to enable re-open */
		os_free(last_path);
		last_path = os_strdup(path);
	}

	out_file = fopen(path, "w");
	if (out_file == NULL) {
		dnss_printf(DNSS_ERROR, "dnss_debug_open_file: Failed to open "
			   "output file, using standard output\n");
		return -1;
	}

	return 0;
}


void dnss_debug_close_file(void)
{
	if (!out_file)
		return;
	fclose(out_file);
	out_file = NULL;
	os_free(last_path);
	last_path = NULL;
}

const char *
safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

