/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_CANNON_LOG_STORE_H
#define _LINUX_CANNON_LOG_STORE_H

#include <linux/stdarg.h>

#ifdef CONFIG_CANNON_BRINGUP
void cannon_log_store_printk(const char *fmt, va_list args);
void cannon_expdb_append(const char *text, unsigned int length);
#else
static inline void cannon_log_store_printk(const char *fmt, va_list args) { }
#endif

#endif
