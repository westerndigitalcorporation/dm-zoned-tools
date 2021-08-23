// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * This file is part of dm-zoned tools.
 * Copyright (C) 2020, SUSE Linux. All rights reserved.
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
#include <libkmod.h>
#include <asm/byteorder.h>

#include <libdevmapper.h>

int dmz_load_module(const char *modname, int log_level)
{
	struct kmod_ctx *ctx = kmod_new(NULL, NULL);
	struct kmod_list *modlist = NULL, *itr;
	int state, ret;

	if (!ctx)
		return -ENOMEM;
	kmod_load_resources(ctx);
	ret = kmod_module_new_from_lookup(ctx, modname, &modlist);
	if (ret < 0) {
		(void)kmod_unref(ctx);
		return ret;
	}
	if (!modlist) {
		fprintf(stderr, "Module '%s' not present\n", modname);
		(void)kmod_unref(ctx);
		return -ENOENT;
	}
	kmod_list_foreach(itr, modlist) {
		struct kmod_module *mod = NULL;

		mod = kmod_module_get_module(itr);
		if (!mod)
			continue;
		state = kmod_module_get_initstate(mod);
		if (state == KMOD_MODULE_BUILTIN) {
			if (log_level)
				printf("Module '%s' built-in\n", modname);
			(void)kmod_module_unref(mod);
			continue;
		}
		if (state == KMOD_MODULE_LIVE) {
			if (log_level)
				printf("Module '%s' already loaded\n", modname);
			(void)kmod_module_unref(mod);
			continue;
		}
		ret = kmod_module_probe_insert_module(mod,
			KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
		if (ret) {
			if (ret == KMOD_PROBE_APPLY_BLACKLIST) {
				fprintf(stderr,
					"Module '%s' is blacklisted\n",
					modname);
				ret = -ENXIO;
			} else {
				fprintf(stderr,
					"Module '%s' not loaded, error %d\n",
					modname, ret);
			}
		} else if (log_level)
			printf("Module '%s' loaded\n", modname);
		(void)kmod_module_unref(mod);
		if (ret)
			break;
	}
	kmod_module_unref_list(modlist);
	(void)kmod_unref(ctx);
	return ret;
}

int dmz_init_dm(int log_level)
{
	struct dm_task *dmt;
	struct dm_versions *tgt, *last_tgt;
	int ret = -ENXIO;

	dm_log_with_errno_init(NULL);

	if (log_level > 1)
		dm_log_init_verbose(log_level - 1);

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
			switch (tgt->version[0]) {
			case DMZ_DM_VER:
				/* Interface v3 uses v2 metadata */
				/* fall through */
			case 2:
				ret = DMZ_META_VER;
				break;
			case 1:
				ret = tgt->version[0];
				break;
			default:
				fprintf(stderr,
					"Unsupported dm-zoned version %d.%d.%d\n",
					tgt->version[0], tgt->version[1],
					tgt->version[2]);
				ret = -EINVAL;
				break;
			}
		}
		tgt = (void *) tgt + tgt->next;
	} while (last_tgt != tgt);

	dm_task_destroy(dmt);
	if (ret < 0)
		fprintf(stderr, "dm-zoned target not supported\n");

	return ret;
}

int dmz_create_dm(struct dmz_dev *dev)
{
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint32_t cookie = 0;
	__u64 capacity = dev->nr_zones * dev->zone_nr_sectors;
	__u16 udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;
	char params[4096];

	/*
	 * dm-zoned interface version 3 allows for capacity
	 * being different than the resulting device size.
	 */
	capacity = dev->nr_chunks * dev->zone_nr_sectors;

	if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
		return -ENOMEM;

	if (!dm_task_set_name (dmt, dev->label))
		goto out;

	if (dev->sb_version > 1 && dev->nr_bdev > 1) {
		int i;
		unsigned len = 0;

		for (i = 0; i < dev->nr_bdev; i++) {
			len += snprintf(params + len, 4096 - len,
					"%s ", dev->bdev[i].path);
		}
	} else {
		sprintf(params, "%s", dev->bdev[0].path);
		if (dmz_mod_ver == 1) {
			/*
			 * V1 kernel modules (prior to kernels 5.8) wrongly
			 * require the entire backend device capacity to be
			 * specified.
			 */
			capacity = dev->bdev[0].capacity;
		}
	}

	if (!dm_task_add_target(dmt, 0, capacity, "zoned", params))
		goto out;

	if (dev->flags & DMZ_VERBOSE)
		printf("%s: table 0 %llu zoned %s\n", dev->label,
		       capacity, params);

	if (dev->sb_version > 1) {
		char prefixed_uuid[UUID_STR_LEN + 4];

		sprintf(prefixed_uuid, "dmz-");
		uuid_unparse(dev->uuid, prefixed_uuid + 4);
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

int dmz_check_dm_target(struct dmz_dev *dev, char *dm_dev)
{
	int ret = -EINVAL;
	struct dm_task *dmt;
	uint64_t start, length;
	char *target_type, *params;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		return -ENOMEM;

	if (!dm_task_set_name(dmt, dm_dev)) {
		ret = -ENOMEM;
		goto out;
	}

	dm_task_no_open_count(dmt);

	if (!dm_task_run(dmt)) {
		ret = -EINVAL;
		goto out;
	}
	dm_get_next_target(dmt, NULL, &start, &length, &target_type, &params);
	if (strlen(target_type) == 5 &&
	    !strncmp(target_type, "zoned", 5)) {
		strcpy(dev->label, dm_task_get_name(dmt));
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

	if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
		return -ENOMEM;

	if (!dm_task_set_name(dmt, dm_dev)) {
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
			dev->bdev[0].name, DMZ_MAGIC, __le32_to_cpu(sb->magic));
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
			dev->bdev[0].name, calculated_crc, stored_crc);
		ret = -EINVAL;
		goto out;
	}

	/* Check UUID for V2 metadata */
	dev->sb_version = __le32_to_cpu(sb->version);
	switch (dev->sb_version) {
	case DMZ_DM_VER:
	case 2:
		if (uuid_is_null(sb->dmz_uuid)) {
			fprintf(stderr, "%s: DM-Zoned UUID is null\n",
				dev->bdev[0].name);
			ret = -EINVAL;
			goto out;
		}
		uuid_copy(dev->uuid, sb->dmz_uuid);
		strncpy(dev->label, (const char *)sb->dmz_label,
			DMZ_LABEL_LEN);
		break;
	case 1:
		break;
	default:
		fprintf(stderr,
			"%s: invalid metadata version %u\n",
			dev->bdev[0].name, dev->sb_version);
	}

	/* OK */
	if (dev->flags & DMZ_VERBOSE)
		printf("%s: loaded superblock (version %d, generation %llu)\n",
		       dev->bdev[0].name, __le32_to_cpu(sb->version),
		       __le64_to_cpu(sb->gen));

out:
	free(sb);
	return ret;
}

int dmz_start(struct dmz_dev *dev)
{
	/* Calculate metadata location */
	if (dmz_locate_metadata(dev) < 0) {
		fprintf(stderr,
			"Failed to locate metadata\n");
		return -1;
	}

	/* Check primary super block */
	if (dev->flags & DMZ_VERBOSE)
		printf("Primary metadata set at block %llu (zone %u)\n",
		       dev->sb_block, dmz_zone_id(dev, dev->sb_zone));

	if (dmz_load_sb(dev) < 0) {
		fprintf(stderr,
			"Failed to load metadata\n");
		return -1;
	}

	/* Generate dm name */
	dmz_get_label(dev, dev->label, true);

	if (dev->sb_version > 1) {
		char dmz_uuid[UUID_STR_LEN];

		uuid_unparse(dev->uuid, dmz_uuid);
		printf("%s: starting %s, metadata ver. %u, uuid %s\n",
		       dev->bdev[0].name, dev->label,
		       dev->sb_version, dmz_uuid);
	} else {
		printf("%s: starting %s, metadata ver. %u,\n",
		       dev->bdev[0].name, dev->label,
		       dev->sb_version);
	}

	if (dmz_create_dm(dev)) {
		fprintf(stderr,
			"Failed to start %s\n", dev->label);
		return -1;
	}

	return 0;
}

int dmz_stop(struct dmz_dev *dev, char *dm_name)
{
	int ret, log_level = 0;
	char dm_dev[PATH_MAX];

	dm_log_with_errno_init(NULL);

	if (dev->flags & DMZ_VVERBOSE)
		log_level++;
	dm_log_init_verbose(log_level);

	sprintf(dm_dev, "/dev/%s", dm_name);
	ret = dmz_check_dm_target(dev, dm_dev);
	if (ret < 0) {
		fprintf(stderr,
			"%s: dm device %s is not a zoned target device\n",
			dev->bdev[0].name, dm_name);
		return ret;
	}

	printf("%s: stopping %s\n",
	       dev->bdev[0].name, dev->label);

	ret = dmz_deactivate_dm(dm_dev);
	if (ret < 0) {
		fprintf(stderr,
			"%s: could not deactivate %s\n",
			dev->bdev[0].name, dev->label);
		return ret;
	}

	return 0;
}
