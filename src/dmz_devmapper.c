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

int dmz_create_dm(struct dmz_dev_set *set, int idx)
{
	struct dmz_dev *dev = &set->dev[idx];
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint32_t cookie = 0;
	__u64 capacity = dev->nr_zones * dev->zone_nr_sectors;
	__u16 udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	/*
	 * dm-zoned interface version 3 allows for capacity
	 * being different than the resulting device size.
	 */
	if (set->if_version > 2)
		capacity = dev->nr_chunks * dev->zone_nr_sectors;

	if (!(dmt = dm_task_create (DM_DEVICE_CREATE)))
		return -ENOMEM;

	if (!dm_task_set_name (dmt, set->dmz_label))
		goto out;

	if (!dm_task_add_target (dmt, 0, capacity, "zoned", dev->path))
		goto out;

	if (dev->sb_version == DMZ_META_VER &&
	    !uuid_is_null(set->dmz_uuid)) {
		char prefixed_uuid[UUID_STR_LEN + 4];


		sprintf(prefixed_uuid, "dmz-");
		uuid_unparse(set->dmz_uuid, prefixed_uuid + 4);
		if (!dm_task_set_uuid(dmt, prefixed_uuid))
			goto out;
	}
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

int dmz_check_dm_target(struct dmz_dev_set *set, char *dm_dev)
{
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint64_t start, length;
	char *target_type, *params;

	if (!(dmt = dm_task_create (DM_DEVICE_TABLE)))
		return -ENOMEM;

	if (!dm_task_set_name (dmt, dm_dev)) {
		ret = -ENOMEM;
		goto out;
	}

	dm_task_no_open_count(dmt);

	if (!dm_task_run (dmt)) {
		ret = -EINVAL;
		goto out;
	}
	dm_get_next_target(dmt, NULL, &start, &length,
			   &target_type, &params);
	if (strlen(target_type) == 5 &&
	    !strncmp(target_type, "zoned", 5)) {
		strcpy(set->dmz_label, dm_task_get_name(dmt));
		ret = 0;
	}
out:
	dm_task_destroy(dmt);

	return ret;
}

int dmz_deactivate_dm(char *dm_dev)
{
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint32_t cookie = 0;
	__u16 udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (!(dmt = dm_task_create (DM_DEVICE_REMOVE)))
		return -ENOMEM;

	if (!dm_task_set_name (dmt, dm_dev)) {
		goto out;
	}

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
static int dmz_load_sb(struct dmz_dev_set *set, int idx)
{
	struct dmz_dev *dev = &set->dev[idx];
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

       /* Check UUID for V2 metadata */
	if (__le32_to_cpu(sb->version) == DMZ_META_VER) {
		if (uuid_is_null(sb->dmz_uuid)) {
			fprintf(stderr, "%s: DM-Zoned UUID is null\n",
				dev->name);
			ret = -EINVAL;
			goto out;
		}
		uuid_copy(set->dmz_uuid, sb->dmz_uuid);
		memcpy(set->dmz_label, sb->dmz_label, 32);
		if (uuid_is_null(sb->dev_uuid)) {
			fprintf(stderr, "%s: Device UUID is null\n", dev->name);
			ret = -EINVAL;
			goto out;
		}
		uuid_copy(dev->dev_uuid, sb->dev_uuid);
	}

	/* OK */
	if (set->flags & DMZ_VERBOSE)
		printf("%s: loaded superblock (version %d, generation %llu)\n",
		       dev->name, __le32_to_cpu(sb->version),
		       __le64_to_cpu(sb->gen));

out:
	free(sb);
	return ret;
}

int dmz_init_dm(int log_level)
{
	struct dm_task *dmt;
	struct dm_versions *tgt, *last_tgt;
	int ret = -ENXIO;

	dm_log_with_errno_init(NULL);

	dm_log_init_verbose(log_level);

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		return -ENOMEM;

	dm_task_no_open_count(dmt);

	if (!dm_task_run(dmt)) {
		fprintf(stderr, "Failed to communicated with device-mapper\n");
		return -ENODEV;
	}

	tgt = dm_task_get_versions(dmt);
	do {
		last_tgt = tgt;
		if (!strncmp("zoned", tgt->name, 5)) {
			if (log_level)
				printf("Found dm-zoned version %d.%d.%d\n",
				       tgt->version[0], tgt->version[1],
				       tgt->version[2]);
			ret = 0;
			if (tgt->version[0] == 1) {
				ret = tgt->version[1];
				break;
			}
			fprintf(stderr,
				"Unsupported dm-zoned version %d.%d.%d\n",
				tgt->version[0], tgt->version[1],
				tgt->version[2]);
		}
		tgt = (void *) tgt + tgt->next;
	} while (last_tgt != tgt);

	dm_task_destroy(dmt);
	if (ret < 0)
		fprintf(stderr, "dm-zoned target not supported\n");
	return ret;
}

int dmz_start(struct dmz_dev_set *set)
{
	int idx = 0;
	struct dmz_dev *dev = &set->dev[idx];

	/* Calculate metadata location */
	if (set->flags & DMZ_VERBOSE)
		printf("%s: Locating metadata...\n", dev->name);
	if (dmz_locate_metadata(set, idx) < 0) {
		fprintf(stderr,
			"%s: Failed to locate metadata\n", dev->name);
		return -1;
	}

	/* Check primary super block */
	if (set->flags & DMZ_VERBOSE)
		printf("%s: Primary metadata set at block %llu (zone %u)\n",
		       dev->name, dev->sb_block,
		       dmz_zone_id(dev, dev->sb_zone));

	if (dmz_load_sb(set, idx) < 0) {
		fprintf(stderr,
			"%s: Failed to load metadata\n", dev->name);
		return -1;
	}

	/* Generate dm name if not set */
	if (!strlen(set->dmz_label))
		sprintf(set->dmz_label, "dmz-%s", dev->name);

	if (!uuid_is_null(set->dmz_uuid)) {
		char dmz_uuid[UUID_STR_LEN];

		uuid_unparse(set->dmz_uuid, dmz_uuid);
		printf("%s: starting %s uuid %s\n",
		       dev->name, set->dmz_label, dmz_uuid);
	} else
		printf("%s: starting %s\n",
		       dev->name, set->dmz_label);

	if (dmz_create_dm(set, idx)) {
		fprintf(stderr,
			"%s: Failed to start %s", dev->name, set->dmz_label);
		return -1;
	}
	return 0;
}

int dmz_stop(struct dmz_dev_set *set, char *dm_name)
{
	struct dmz_dev *dev = &set->dev[0];
	int ret, log_level = 0;
	char dm_dev[PATH_MAX];

	dm_log_with_errno_init(NULL);

	if (set->flags & DMZ_VVERBOSE)
		log_level++;
	dm_log_init_verbose(log_level);

	sprintf(dm_dev, "/dev/%s", dm_name);
	ret = dmz_check_dm_target(set, dm_dev);
	if (ret < 0) {
		fprintf(stderr,
			"%s: dm device %s is not a zoned target device\n",
			dev->name, dm_name);
		return ret;
	}

	printf("%s: stopping %s\n",
	       dev->name, set->dmz_label);

	ret = dmz_deactivate_dm(dm_dev);
	if (ret < 0) {
		fprintf(stderr,
			"%s: could not deactivate %s\n",
			dev->name, set->dmz_label);
		return ret;
	}
	return 0;
}
