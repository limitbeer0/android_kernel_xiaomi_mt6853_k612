// SPDX-License-Identifier: GPL-2.0-only
/* cannon-only, opt-in 8MiB printk spool to the original expdb partition.
 * Capture never performs I/O or waits on the writer. A separate worker copies
 * at most 64KiB under a short lock, writes sectors, then commits a CRC header.
 * Keep the firmware's last 2MiB log_store window independent.
 */
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/cannon_log_store.h>
#include <linux/crc32.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/random.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#define EXPDB_BYTES (40ULL * SZ_1M)
#define DISK_OFFSET (24ULL * SZ_1M)
#define DISK_HEADER_SIZE SZ_4K
#define RING_SIZE SZ_8M
#define TRANSFER_SIZE SZ_64K
#define EXPDB_UUID "3b9e343b-cdc8-4d7f-9fa6-b6812e50ab62"

struct cannon_disk_header {
	char magic[8];
	__le32 version;
	__le32 header_size;
	__le32 data_size;
	__le32 reserved;
	__le64 cookie;
	__le64 committed;
	__le64 produced;
	__le64 dropped;
	__le32 flushes;
	__le32 crc;
};

static char ring[RING_SIZE];
static DEFINE_RAW_SPINLOCK(ring_lock);
static atomic_t dropped_records = ATOMIC_INIT(0);
static u64 produced, committed, cookie;
static unsigned int flushes;
static bool enabled;
static unsigned int writer_seconds = 120;
static struct file *expdb_file;
static struct block_device *expdb_bdev;
static void *transfer;
static void *header_page;
static unsigned long deadline;
static struct workqueue_struct *writer_queue;
static void expdb_write_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(writer_work, expdb_write_work);

static int __init cannon_expdb_param(char *value)
{
	if (!value || strcmp(value, "1"))
		return -EINVAL;
	enabled = true;
	return 0;
}
early_param("cannon.expdb", cannon_expdb_param);

static int __init cannon_expdb_seconds_param(char *value)
{
	unsigned int seconds;

	if (!value || kstrtouint(value, 0, &seconds) || seconds < 120 || seconds > 660)
		return -EINVAL;
	writer_seconds = seconds;
	return 0;
}
early_param("cannon.expdb_seconds", cannon_expdb_seconds_param);

void cannon_expdb_append(const char *text, unsigned int length)
{
	unsigned long flags;
	u32 offset, first;

	if (!READ_ONCE(enabled) || !length)
		return;
	if (!raw_spin_trylock_irqsave(&ring_lock, flags)) {
		atomic_inc(&dropped_records);
		return;
	}
	offset = produced % RING_SIZE;
	first = min_t(u32, length, RING_SIZE - offset);
	memcpy(ring + offset, text, first);
	memcpy(ring, text + first, length - first);
	produced += length;
	raw_spin_unlock_irqrestore(&ring_lock, flags);
}

static int match_expdb(struct device *device, const void *unused)
{
	struct block_device *bdev = dev_to_bdev(device);

	return bdev->bd_meta_info && bdev_partno(bdev) == 4 &&
	       !strcmp(bdev->bd_meta_info->volname, "expdb") &&
	       !strcasecmp(bdev->bd_meta_info->uuid, EXPDB_UUID) &&
	       bdev_nr_bytes(bdev) == EXPDB_BYTES;
}

static int open_expdb(void)
{
	struct device *device;
	struct file *file;

	device = class_find_device(&block_class, NULL, NULL, match_expdb);
	if (!device)
		return -ENODEV;
	file = bdev_file_open_by_dev(device->devt,
			BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_RESTRICT_WRITES,
			&writer_work, NULL);
	put_device(device);
	if (IS_ERR(file))
		return PTR_ERR(file);
	expdb_bdev = file_bdev(file);
	if (bdev_nr_bytes(expdb_bdev) != EXPDB_BYTES ||
	    bdev_logical_block_size(expdb_bdev) > SZ_4K) {
		fput(file);
		expdb_bdev = NULL;
		return -EINVAL;
	}
	expdb_file = file;
	pr_notice("cannon-expdb: 8MiB direct spool opened %pg at offset=%llu cookie=%016llx\n",
		  expdb_bdev, DISK_OFFSET, cookie);
	return 0;
}

static int write_sectors(void *buffer, size_t size, u64 position)
{
	struct bio *bio;
	size_t offset;
	int result;

	if (position < DISK_OFFSET ||
	    position + size > DISK_OFFSET + DISK_HEADER_SIZE + RING_SIZE ||
	    !IS_ALIGNED(position, SZ_4K) || !IS_ALIGNED(size, SZ_4K))
		return -ERANGE;
	bio = bio_alloc(expdb_bdev, size / PAGE_SIZE,
			REQ_OP_WRITE | REQ_SYNC | REQ_FUA, GFP_NOIO);
	if (!bio)
		return -ENOMEM;
	bio->bi_iter.bi_sector = position >> SECTOR_SHIFT;
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		if (bio_add_page(bio, virt_to_page(buffer + offset), PAGE_SIZE, 0) != PAGE_SIZE) {
			bio_put(bio);
			return -EIO;
		}
	}
	result = submit_bio_wait(bio);
	bio_put(bio);
	return result;
}

static int write_header(u64 count, u64 seen)
{
	struct cannon_disk_header *header = header_page;

	memset(header_page, 0, DISK_HEADER_SIZE);
	memcpy(header->magic, "CNL6DIS1", 8);
	header->version = cpu_to_le32(1);
	header->header_size = cpu_to_le32(DISK_HEADER_SIZE);
	header->data_size = cpu_to_le32(RING_SIZE);
	header->cookie = cpu_to_le64(cookie);
	header->committed = cpu_to_le64(count);
	header->produced = cpu_to_le64(seen);
	header->dropped = cpu_to_le64(atomic_read(&dropped_records));
	header->flushes = cpu_to_le32(flushes);
	header->crc = cpu_to_le32(crc32_le(~0, header_page, 60) ^ ~0);
	return write_sectors(header_page, DISK_HEADER_SIZE, DISK_OFFSET);
}

static int copy_and_write(void)
{
	unsigned long flags;
	u64 start, end, seen;
	u32 offset, count, actual;
	int result;

	raw_spin_lock_irqsave(&ring_lock, flags);
	seen = produced;
	if (seen == committed) {
		raw_spin_unlock_irqrestore(&ring_lock, flags);
		return 0;
	}
	start = round_down(committed, (u64)SZ_4K);
	/* If I/O fell behind, retain the newest complete window, never index
	 * bytes that the producer has already overwritten. */
	if (seen - start > RING_SIZE)
		start = round_up(seen - RING_SIZE, (u64)SZ_4K);
	offset = start % RING_SIZE;
	count = min_t(u64, round_up(seen - start, (u64)SZ_4K), TRANSFER_SIZE);
	count = min_t(u32, count, RING_SIZE - offset);
	actual = min_t(u64, count, seen - start);
	memcpy(transfer, ring + offset, actual);
	raw_spin_unlock_irqrestore(&ring_lock, flags);
	memset(transfer + actual, 0, count - actual);
	end = start + actual;
	result = write_sectors(transfer, count,
			      DISK_OFFSET + DISK_HEADER_SIZE + offset);
	if (result)
		return result;
	flushes++;
	result = write_header(end, seen);
	if (result)
		return result;
	committed = end;
	return 1;
}

static void expdb_write_work(struct work_struct *work)
{
	int result = 0, i;

	if (time_after(jiffies, deadline))
		return;
	if (!expdb_file) {
		result = open_expdb();
		if (result == -ENODEV)
			goto retry;
		if (result)
			goto failure;
		/* Invalidate any previous boot's direct-spool header first. */
		result = write_header(0, 0);
		if (result)
			goto failure;
	}
	for (i = 0; i < 16; i++) {
		result = copy_and_write();
		if (result <= 0)
			break;
	}
	if (result < 0)
		goto failure;
retry:
	queue_delayed_work(writer_queue, &writer_work, msecs_to_jiffies(250));
	return;
failure:
	pr_err("cannon-expdb: direct spool stopped, error=%d committed=%llu\n",
	       result, committed);
	/* Preserve the last good commit and leave native SRAM logging active. */
	if (expdb_file)
		fput(expdb_file);
	expdb_file = NULL;
}

static int __init cannon_expdb_init(void)
{
	BUILD_BUG_ON(sizeof(struct cannon_disk_header) != 64);
	BUILD_BUG_ON(DISK_OFFSET + DISK_HEADER_SIZE + RING_SIZE > EXPDB_BYTES - SZ_2M);
	if (!enabled || !of_machine_is_compatible("xiaomi,cannon"))
		return 0;
	transfer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(TRANSFER_SIZE));
	header_page = (void *)get_zeroed_page(GFP_KERNEL);
	if (!transfer || !header_page) {
		free_pages((unsigned long)transfer, get_order(TRANSFER_SIZE));
		free_page((unsigned long)header_page);
		return -ENOMEM;
	}
	cookie = get_random_u64();
	deadline = jiffies + writer_seconds * HZ;
	writer_queue = alloc_workqueue("cannon-expdb", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!writer_queue) {
		free_pages((unsigned long)transfer, get_order(TRANSFER_SIZE));
		free_page((unsigned long)header_page);
		return -ENOMEM;
	}
	queue_delayed_work(writer_queue, &writer_work, msecs_to_jiffies(250));
	pr_notice("cannon-expdb: 8MiB capture armed, waiting for GPT expdb; maximum writer lifetime %us\n",
		  writer_seconds);
	return 0;
}
late_initcall(cannon_expdb_init);
