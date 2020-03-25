/*
 * This file is part of dm-zoned tools.
 *
 * Copyright (C) 2020, SUSE Linux. All rights reserved.
 *
 * This software is distributed under the terms of the BSD 2-clause license,
 * "as is," without technical support, and WITHOUT ANY WARRANTY, without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. You should have received a copy of the BSD 2-clause license along
 * with dm-zoned tools.
 * If not, see <http://opensource.org/licenses/BSD-2-Clause>.
 *
 * Authors: Hannes Reinecke (hare@suse.com)
 */

#include "dmz.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <asm/byteorder.h>

#include <libdevmapper.h>

int dmz_create_dm(struct dmz_dev *dev)
{
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint32_t cookie = 0;
	int log_level = 0;
	__u64 capacity = dev->nr_zones * dev->zone_nr_sectors;
	__u16 udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	dm_log_with_errno_init(NULL);

	if (dev->flags & DMZ_VVERBOSE)
		log_level++;
	dm_log_init_verbose(log_level);

	if (!(dmt = dm_task_create (DM_DEVICE_CREATE)))
		return -ENOMEM;

	if (!dm_task_set_name (dmt, dev->dmz_label))
		goto out;

	if (!dm_task_add_target (dmt, 0, capacity, "zoned", dev->path))
		goto out;

	dm_task_skip_lockfs(dmt);
	dm_task_no_flush(dmt);
	dm_task_no_open_count(dmt);

	if (dm_task_set_cookie(dmt, &cookie, udev_flags)) {
		if (dm_task_run (dmt)) {
			dm_udev_wait(cookie);
			ret = 0;
		}
	}

out:
	dm_task_destroy(dmt);

	return ret;
}

/*
 * Load the contents of a super block
 */
static int dmz_load_sb(struct dmz_dev *dev)
{
	struct dm_zoned_super *sb;
	unsigned char *buf;
	__u32 stored_crc, calculated_crc;
	int ret;

	buf = malloc(DMZ_BLOCK_SIZE);
	if (!buf)
		return -ENOMEM;

	sb = (struct dm_zoned_super *)buf;
	ret = dmz_read_block(dev, dev->sb_block, buf);
	if (ret != 0) {
		ret = -EIO;
		goto out;
	}

	/* Check magic */
	if (__le32_to_cpu(sb->magic) != DMZ_MAGIC) {
		fprintf(stderr,
			"%s: invalid magic (expected 0x%08x read 0x%08x)\n",
			dev->name, DMZ_MAGIC, __le32_to_cpu(sb->magic));
		ret = -EINVAL;
		goto out;
	}

	/* Check CRC */
	stored_crc = __le32_to_cpu(sb->crc);
	sb->crc = 0;
	calculated_crc = dmz_crc32(sb->gen, buf, DMZ_BLOCK_SIZE);
	if (calculated_crc != stored_crc) {
		fprintf(stderr,
			"%s: invalid crc (expected 0x%08x, read 0x%08x)\n",
			dev->name, calculated_crc, stored_crc);
		ret = -EINVAL;
		goto out;
	}

	/* Check version */
	if (__le32_to_cpu(sb->version) > DMZ_META_VER) {
		fprintf(stderr,
			"%s: invalid version (expected 0x%x, read 0x%x)\n",
			dev->name, DMZ_META_VER, __le32_to_cpu(sb->version));
		ret = -EINVAL;
		goto out;
	}

	/* OK */
	if (dev->flags & DMZ_VERBOSE)
		printf("%s: loaded superblock (version %d, generation %llu)\n",
		       dev->name, __le32_to_cpu(sb->version),
		       __le64_to_cpu(sb->gen));

out:
	free(sb);
	return ret;
}

int dmz_start(struct dmz_dev *dev)
{
	/* Calculate metadata location */
	if (dev->flags & DMZ_VERBOSE)
		printf("%s: Locating metadata...\n", dev->name);
	if (dmz_locate_metadata(dev) < 0) {
		fprintf(stderr,
			"%s: Failed to locate metadata\n", dev->name);
		return -1;
	}

	/* Check primary super block */
	if (dev->flags & DMZ_VERBOSE)
		printf("%s: Primary metadata set at block %llu (zone %u)\n",
		       dev->name, dev->sb_block,
		       dmz_zone_id(dev, dev->sb_zone));

	if (dmz_load_sb(dev) < 0) {
		fprintf(stderr,
			"%s: Failed to load metadata\n", dev->name);
		return -1;
	}

	/* Generate dm name if not set */
	if (!strlen(dev->dmz_label))
		sprintf(dev->dmz_label, "dmz-%s", dev->name);

	printf("%s: starting %s\n",
	       dev->name, dev->dmz_label);

	if (dmz_create_dm(dev)) {
		fprintf(stderr,
			"%s: Failed to start %s", dev->name, dev->dmz_label);
		return -1;
	}
	return 0;
}
