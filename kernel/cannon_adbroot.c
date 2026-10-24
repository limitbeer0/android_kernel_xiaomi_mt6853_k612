// SPDX-License-Identifier: GPL-2.0-only
/* Diagnostic-only adbd bootstrap, based on tiann/KernelSU's adb_root feature.
 * Opt in with cannon.adbroot=1. Only PID1's root-owned, non-writable adbd ELF
 * is selected. Prepare the shim in final /dev tmpfs, then pin the existing su
 * SELinux context across exec. Other system services retain their policy.
 */
#include <linux/binfmts.h>
#include <linux/cannon_adbroot.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/string.h>
#include "cannon_adbroot_blob.h"

static bool enabled;

static int __init cannon_adbroot_param(char *value)
{
	if (!value || strcmp(value, "1"))
		return -EINVAL;
	enabled = true;
	return 0;
}
early_param("cannon.adbroot", cannon_adbroot_param);

bool cannon_adbroot_enabled(void)
{
	return enabled && of_machine_is_compatible("xiaomi,cannon");
}

void cannon_adbroot_disable(void)
{
	enabled = false;
}

static bool target_adbd(struct linux_binprm *bprm)
{
	struct inode *inode = file_inode(bprm->file);
	const char *name = bprm->filename;
	size_t length = strlen(name);
	bool path;

	path = !strcmp(name, "/system/bin/adbd") ||
	       (!strncmp(name, "/apex/com.android.adbd", 22) &&
		length > 9 && !strcmp(name + length - 9, "/bin/adbd"));
	return path && uid_eq(current_uid(), GLOBAL_ROOT_UID) &&
	       task_ppid_nr(current) == 1 && uid_eq(inode->i_uid, GLOBAL_ROOT_UID) &&
	       S_ISREG(inode->i_mode) && !(inode->i_mode & 0022);
}

bool cannon_adbroot_prepare(struct linux_binprm *bprm)
{
	struct cred *cred;
	const struct cred *old;
	struct file *file;
	loff_t position = 0;
	ssize_t written;
	int result;

	if (!cannon_adbroot_enabled() || !target_adbd(bprm))
		return false;
	cred = prepare_creds();
	if (!cred)
		return false;
	result = cannon_adbroot_cred_security(cred);
	if (result) {
		pr_err("cannon-adbroot: su context unavailable: %d\n", result);
		abort_creds(cred);
		return false;
	}
	cred->uid = cred->euid = cred->suid = cred->fsuid = GLOBAL_ROOT_UID;
	cred->gid = cred->egid = cred->sgid = cred->fsgid = GLOBAL_ROOT_GID;
	cred->cap_effective = cred->cap_permitted = CAP_FULL_SET;
	cred->cap_inheritable = cred->cap_bset = cred->cap_ambient = CAP_FULL_SET;
	old = override_creds(cred);
	file = filp_open("/dev/cannon-adbroot.so", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0500);
	if (IS_ERR(file)) {
		result = PTR_ERR(file);
	} else {
		written = kernel_write(file, cannon_adbroot_blob, sizeof(cannon_adbroot_blob), &position);
		result = written == sizeof(cannon_adbroot_blob) ? 0 : -EIO;
		fput(file);
	}
	revert_creds(old);
	if (result) {
		pr_err("cannon-adbroot: shim creation failed: %d\n", result);
		abort_creds(cred);
		return false;
	}
	commit_creds(cred);
	pr_notice("cannon-adbroot: authenticated adbd bootstrap enabled, shim=%zu bytes\n",
		  sizeof(cannon_adbroot_blob));
	return true;
}
