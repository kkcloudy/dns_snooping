/*
 * ARP Proxy / Debug prints
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DEBUG_H
#define DEBUG_H

/* Debugging function - conditional printf and hex dump. Driver wrappers can
 * use these for debugging purposes. */

enum {
	DNSS_EXCESSIVE, DNSS_MSGDUMP, DNSS_DEBUG, DNSS_INFO, DNSS_WARNING, DNSS_ERROR
};

int dnss_debug_open_file(const char *path);
int dnss_debug_reopen_file(void);
void dnss_debug_close_file(void);

/**
 * dnss_debug_printf_timestamp - Print timestamp for debug output
 *
 * This function prints a timestamp in seconds_from_1970.microsoconds
 * format if debug output has been configured to include timestamps in debug
 * messages.
 */
void dnss_debug_print_timestamp(void);

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
PRINTF_FORMAT(2, 3);

/**
 * dnss_hexdump - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump.
 */
void dnss_hexdump(int level, const char *title, const u8 *buf, size_t len);

/**
 * dnss_hexdump_key - conditional hex dump, hide keys
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump. This works
 * like dnss_hexdump(), but by default, does not include secret keys (passwords,
 * etc.) in debug output.
 */
void dnss_hexdump_key(int level, const char *title, const u8 *buf, size_t len);

/**
 * dnss_hexdump_ascii - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump with both
 * the hex numbers and ASCII characters (for printable range) are shown. 16
 * bytes per line will be shown.
 */
void dnss_hexdump_ascii(int level, const char *title, const u8 *buf,
		       size_t len);

/**
 * dnss_hexdump_ascii_key - conditional hex dump, hide keys
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of buf is printed out has hex dump with both
 * the hex numbers and ASCII characters (for printable range) are shown. 16
 * bytes per line will be shown. This works like dnss_hexdump_ascii(), but by
 * default, does not include secret keys (passwords, etc.) in debug output.
 */
void dnss_hexdump_ascii_key(int level, const char *title, const u8 *buf,
			   size_t len);

void dnss_debug_open_syslog(void);
void dnss_debug_close_syslog(void);
const char * debug_level_str(int level);
int str_to_debug_level(const char *s);
const char *safe_strerror(int errnum);

#endif /* DEBUG_H */
