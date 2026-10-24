/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_CANNON_ADBROOT_H
#define _LINUX_CANNON_ADBROOT_H
#include <linux/types.h>
struct cred;
struct linux_binprm;
#ifdef CONFIG_CANNON_BRINGUP
bool cannon_adbroot_enabled(void);
void cannon_adbroot_disable(void);
bool cannon_adbroot_prepare(struct linux_binprm *bprm);
int cannon_adbroot_cred_security(struct cred *cred);
#else
static inline bool cannon_adbroot_enabled(void) { return false; }
static inline bool cannon_adbroot_prepare(struct linux_binprm *bprm) { return false; }
#endif
#endif
