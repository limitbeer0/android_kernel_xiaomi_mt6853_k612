// SPDX-License-Identifier: GPL-2.0-only
/*
 * cannon's original Preloader already saves a kernel buffer through the
 * SRAM log_store ABI. Publish a private, cache-cleaned diagnostic buffer;
 * leave the PL/LK DRAM log and the original ramoops allocation untouched.
 * Opt in with cannon.log_store=1. No storage I/O is issued by this code.
 */
#include <linux/atomic.h>
#include <linux/cannon_log_store.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/sched/clock.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <asm/memory.h>

#define CANNON_SRAM_PA 0x11df00
#define CANNON_SRAM_SIZE 0x100
#define CANNON_LOG_SIZE SZ_512K
#define CANNON_HEAD_SIZE SZ_128K

/* Little-endian wire format, also decoded by cannon/read_expdb.py. */
struct cannon_log_header {
	char magic[8];
	__le32 version;
	__le32 total_size;
	__le32 head_size;
	__le32 tail_size;
	__le32 head_used;
	__le32 tail_next;
	__le32 tail_used;
	__le32 dropped;
	__le32 records;
	__le32 bytes_lo;
	__le32 bytes_hi;
	__le32 reserved[3];
};

#define CANNON_TAIL_SIZE (CANNON_LOG_SIZE - sizeof(struct cannon_log_header) - CANNON_HEAD_SIZE)

static struct {
	struct cannon_log_header h;
	char head[CANNON_HEAD_SIZE];
	char tail[CANNON_TAIL_SIZE];
} mirror __aligned(64) = {
	.h = {
		.magic = "CNL6LOG1",
		.version = cpu_to_le32(1),
		.total_size = cpu_to_le32(CANNON_LOG_SIZE),
		.head_size = cpu_to_le32(CANNON_HEAD_SIZE),
		.tail_size = cpu_to_le32(CANNON_TAIL_SIZE),
	},
};

static DEFINE_RAW_SPINLOCK(mirror_lock);
static atomic_t dropped = ATOMIC_INIT(0);
static bool enabled;
static bool published;
static u64 bytes_seen;
static u32 head_used, tail_next, tail_used, records;

static int __init cannon_log_store_param(char *value)
{
	if (!value || strcmp(value, "1"))
		return -EINVAL;
	enabled = true;
	return 0;
}
early_param("cannon.log_store", cannon_log_store_param);

static void clean_written(void *start, size_t length)
{
	if (published && length)
		dcache_clean_poc((unsigned long)start,
				 (unsigned long)start + length);
}

void cannon_log_store_printk(const char *fmt, va_list args)
{
	unsigned long flags;
	va_list copy;
	char text[512];
	u32 n, prefix, count, first;
	u64 now;

	if (!READ_ONCE(enabled))
		return;
	/* Never wait on a recursively interrupted printk, including NMI. */
	if (!raw_spin_trylock_irqsave(&mirror_lock, flags)) {
		atomic_inc(&dropped);
		return;
	}
	now = local_clock();
	prefix = scnprintf(text, sizeof(text), "[%5llu.%06llu] ",
			   now / NSEC_PER_SEC, (now % NSEC_PER_SEC) / NSEC_PER_USEC);
	va_copy(copy, args);
	n = prefix + vscnprintf(text + prefix, sizeof(text) - prefix, fmt, copy);
	va_end(copy);
	if (!n)
		goto unlock;

	count = min_t(u32, n, CANNON_HEAD_SIZE - head_used);
	memcpy(mirror.head + head_used, text, count);
	clean_written(mirror.head + head_used, count);
	head_used += count;
	first = min_t(u32, n, CANNON_TAIL_SIZE - tail_next);
	memcpy(mirror.tail + tail_next, text, first);
	clean_written(mirror.tail + tail_next, first);
	memcpy(mirror.tail, text + first, n - first);
	clean_written(mirror.tail, n - first);
	tail_next = (tail_next + n) % CANNON_TAIL_SIZE;
	tail_used = min_t(u32, tail_used + n, CANNON_TAIL_SIZE);
	bytes_seen += n;
	mirror.h.head_used = cpu_to_le32(head_used);
	mirror.h.tail_next = cpu_to_le32(tail_next);
	mirror.h.tail_used = cpu_to_le32(tail_used);
	mirror.h.dropped = cpu_to_le32(atomic_read(&dropped));
	mirror.h.records = cpu_to_le32(++records);
	mirror.h.bytes_lo = cpu_to_le32(lower_32_bits(bytes_seen));
	mirror.h.bytes_hi = cpu_to_le32(upper_32_bits(bytes_seen));
	/* Commit metadata after its text has reached DRAM. */
	clean_written(&mirror.h, sizeof(mirror.h));
unlock:
	raw_spin_unlock_irqrestore(&mirror_lock, flags);
	cannon_expdb_append(text, n);
}

static int __init cannon_log_store_publish(void)
{
	struct device_node *chosen;
	const __le32 *property;
	void __iomem *sram;
	phys_addr_t physical;
	unsigned long flags;
	u32 old_flags;
	int length;

	BUILD_BUG_ON(sizeof(struct cannon_log_header) != 64);
	BUILD_BUG_ON(sizeof(mirror) != CANNON_LOG_SIZE);
	if (!enabled || !of_machine_is_compatible("xiaomi,cannon"))
		return 0;
	chosen = of_find_node_by_path("/chosen");
	if (!chosen)
		return -ENODEV;
	/* The original MTK property is a native LE struct, not FDT reg cells. */
	property = of_get_property(chosen, "log_store", &length);
	if (!property || length != 8 ||
	    le32_to_cpup(property) != CANNON_SRAM_PA ||
	    le32_to_cpup(property + 1) != CANNON_SRAM_SIZE) {
		of_node_put(chosen);
		pr_err("cannon-log-store: unexpected chosen/log_store ABI\n");
		return -EINVAL;
	}
	of_node_put(chosen);
	physical = __pa_symbol(&mirror);
	/* PL uses 32-bit pointers. Do not truncate an unsupported address. */
	if (physical < 0x40000000 || upper_32_bits(physical + sizeof(mirror) - 1))
		return -ERANGE;
	sram = ioremap_wc(CANNON_SRAM_PA, CANNON_SRAM_SIZE);
	if (!sram)
		return -ENOMEM;
	if (readl(sram) != 0xabcd1234 || readl(sram + 0x0c) != 0x5678ef90 ||
	    readl(sram + 0x14) != 0x7ffbf000 || readl(sram + 0x18) != SZ_256K) {
		pr_err("cannon-log-store: original SRAM header validation failed\n");
		iounmap(sram);
		return -EINVAL;
	}
	raw_spin_lock_irqsave(&mirror_lock, flags);
	dcache_clean_poc((unsigned long)&mirror,
			 (unsigned long)&mirror + sizeof(mirror));
	writel(lower_32_bits(physical), sram + 0x24);
	writel(sizeof(mirror), sram + 0x28);
	wmb();
	old_flags = readl(sram + 0x10);
	/* NEED_SAVE_TO_EMMC + BUFF_EARLY_PRINTK; preserve every other field. */
	writel(old_flags | 0x404, sram + 0x10);
	readl(sram + 0x10);
	published = true;
	raw_spin_unlock_irqrestore(&mirror_lock, flags);
	iounmap(sram);
	pr_notice("cannon-log-store: CNL6LOG1 native expdb buffer %pa size=%zu head=%u tail=%zu flags=%#x\n",
		  &physical, sizeof(mirror), CANNON_HEAD_SIZE,
		  (size_t)CANNON_TAIL_SIZE, old_flags | 0x404);
	return 0;
}
core_initcall(cannon_log_store_publish);
