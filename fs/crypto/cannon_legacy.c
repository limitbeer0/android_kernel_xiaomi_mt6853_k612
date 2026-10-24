// SPDX-License-Identifier: GPL-2.0-only
/*
 * Compatibility with the MT6853 4.14 fscrypt v1 inline-encryption format.
 * keysetup_v1.c used the raw master key for regular-file contents, and
 * inline_crypt.c used (inode_low32 << 32) | logical_block as the UFS DUN.
 * Neither difference is represented in the on-disk v1 policy flags.
 *
 * Opt in explicitly, and only for the stock GPT userdata partition's F2FS
 * AES-XTS v1 contents. Filename encryption, other partitions and v2 policies
 * retain the upstream format. Both inline fallback and software fscrypt need
 * the same contents key/IV to read existing files correctly.
 */
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/kstrtox.h>
#include <linux/magic.h>

#include "fscrypt_private.h"

static bool cannon_legacy_v1;

static int __init cannon_legacy_v1_setup(char *value)
{
	return kstrtobool(value, &cannon_legacy_v1);
}
early_param("cannon.fscrypt_legacy_v1", cannon_legacy_v1_setup);

bool fscrypt_cannon_legacy_v1(const struct fscrypt_inode_info *ci)
{
	const struct super_block *sb = ci->ci_inode->i_sb;
	struct block_device *bdev = sb->s_bdev;

	if (!cannon_legacy_v1 || !S_ISREG(ci->ci_inode->i_mode) ||
	    sb->s_magic != F2FS_SUPER_MAGIC || !bdev || !bdev->bd_meta_info ||
	    strcmp((const char *)bdev->bd_meta_info->volname, "userdata") ||
	    ci->ci_policy.version != FSCRYPT_POLICY_V1 ||
	    ci->ci_policy.v1.contents_encryption_mode != FSCRYPT_MODE_AES_256_XTS ||
	    (ci->ci_policy.v1.flags & ~FSCRYPT_POLICY_FLAGS_PAD_MASK) ||
	    ci->ci_data_unit_bits != 12 || sb->s_blocksize != 4096 ||
	    bdev_physical_block_size(bdev) != 4096)
		return false;

	pr_info_once("cannon-fscrypt: legacy v1 userdata contents key and inode/block IV enabled\n");
	return true;
}
