// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * This file is part of dm-zoned tools.
 * Copyright (C) 2016, Western Digital.  All rights reserved.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Damien Le Moal (damien.lemoal@wdc.com)
 */
#include "dmz.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <asm/byteorder.h>

/*
 * Prepare the zone containing a super block.
 */
static int dmz_prepare_super_zone(struct dmz_dev *dev, __u64 sb_block)
{
	unsigned int zone_id = dmz_block_zone_id(dev, sb_block);
	struct blk_zone *zone = &dev->zones[zone_id];

	/*
	 * For conventional and empty zones, we have nothing to do.
	 * For non-empty seuential zones, reset the zone so that overwrites
	 * of the super block by the relabel or repair operations does not fail.
	 */
	if (dmz_zone_unknown(zone) ||
	    dmz_zone_conv(zone) ||
	    dmz_zone_empty(zone))
		return 0;

	return dmz_reset_zone(dev, zone);
}

/*
 * Fill and write a super block.
 */
int dmz_write_super(struct dmz_dev *dev, __u64 gen, __u64 offset)
{
	__u64 sb_block = dev->sb_block + offset, bdev_sb_block;
	struct dm_zoned_super *sb;
	struct dmz_block_dev *bdev;
	__u32 crc;
	__u8 *buf;
	int ret;

	if (dmz_prepare_super_zone(dev, sb_block))
		return -1;

	buf = malloc(DMZ_BLOCK_SIZE);
	if (!buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}
	memset(buf, 0, DMZ_BLOCK_SIZE);

	bdev = dmz_block_to_bdev(dev, sb_block, &bdev_sb_block);

	printf("  Writing super block to %s block %llu\n",
	       bdev->name, bdev_sb_block);

	sb = (struct dm_zoned_super *) buf;

	sb->magic = __cpu_to_le32(DMZ_MAGIC);
	sb->version = __cpu_to_le32(dev->sb_version);

	sb->gen = __cpu_to_le64(gen);

	sb->sb_block = __cpu_to_le64(sb_block);
	sb->nr_meta_blocks = __cpu_to_le32(dev->nr_meta_blocks);
	sb->nr_reserved_seq = __cpu_to_le32(dev->nr_reserved_seq);
	sb->nr_chunks = __cpu_to_le32(dev->nr_chunks);

	sb->nr_map_blocks = __cpu_to_le32(dev->nr_map_blocks);
	sb->nr_bitmap_blocks = __cpu_to_le32(dev->nr_bitmap_blocks);

	if (dev->sb_version > 1) {
		memcpy(sb->dmz_uuid, dev->uuid, DMZ_UUID_LEN);
		memcpy(sb->dmz_label, dev->label, DMZ_LABEL_LEN);
		memcpy(sb->dev_uuid, bdev->uuid, DMZ_UUID_LEN);
	}
	crc = dmz_crc32(gen, sb, DMZ_BLOCK_SIZE);
	sb->crc = __cpu_to_le32(crc);

	ret = dmz_write_block(dev, sb_block, buf);
	if (ret < 0)
		fprintf(stderr,
			"%s: Write super block at block %llu failed\n",
			bdev->name, bdev_sb_block);

	free(buf);

	return ret;
}

/*
 * Write mapping table blocks.
 */
static int dmz_write_mapping(struct dmz_dev *dev, __u64 offset)
{
	__u64 map_block;
	struct dm_zoned_map *dmap;
	unsigned int i;
	__u8 *buf;
	int ret = -1;

	printf("  Writing mapping table\n");

	/* Setup "all unmapped" mapping block */
	buf = malloc(DMZ_BLOCK_SIZE);
	if (!buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}
	dmap = (struct dm_zoned_map *)buf;
	for (i = 0; i < DMZ_MAP_ENTRIES; i++) {
		dmap->dzone_id = __cpu_to_le32(DMZ_MAP_UNMAPPED);
		dmap->bzone_id = __cpu_to_le32(DMZ_MAP_UNMAPPED);
		dmap++;
	}

	/* Write mapping table */
	map_block = offset + dev->map_block;
	for (i = 0; i < dev->nr_map_blocks; i++) {
		ret = dmz_write_block(dev, map_block + i, buf);
		if (ret < 0) {
			fprintf(stderr,
				"%s: Write mapping block %llu failed\n",
				dev->label,
				map_block + i);
			break;
		}
	}

	free(buf);

	return ret;
}

/*
 * Write zone bitmap blocks.
 */
static int dmz_write_bitmap(struct dmz_dev *dev, __u64 offset)
{
	__u64 bitmap_block;
	unsigned int i;
	__u8 *buf;
	int ret = -1;

	printf("  Writing bitmap blocks\n");

	buf = malloc(DMZ_BLOCK_SIZE);
	if (!buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}
	memset(buf, 0, DMZ_BLOCK_SIZE);

	/* Clear bitmap blocks */
	bitmap_block = offset + dev->bitmap_block;
	for (i = 0; i < dev->nr_bitmap_blocks; i++) {
		ret = dmz_write_block(dev, bitmap_block + i, buf);
		if (ret < 0) {
			fprintf(stderr,
				"%s: Write bitmap block %llu failed\n",
				dev->label,
				bitmap_block + i);
			break;
		}
	}

	free(buf);

	return ret;
}

/*
 * Write formatted metadata blocks.
 */
static int dmz_write_meta(struct dmz_dev *dev, __u64 offset)
{

	/* Write mapping table */
	if (dmz_write_mapping(dev, offset) < 0)
		return -1;

	/* Write bitmap blocks */
	if (dmz_write_bitmap(dev, offset) < 0)
		return -1;

	/* Write super block */
	if (dmz_write_super(dev, 1, offset) < 0)
		return -1;

	return 0;
}

/*
 * Format a device.
 */
int dmz_format(struct dmz_dev *dev)
{
	int i;

	if (dev->sb_version > DMZ_META_VER) {
		dev->sb_version = DMZ_META_VER;
		fprintf(stderr, "Falling back to metadata version %d\n",
			dev->sb_version);
	} else if (!dev->sb_version) {
		dev->sb_version = DMZ_META_VER;
		fprintf(stderr, "Defaulting to metadata version %d\n",
			dev->sb_version);
	}

	/* calculate location of metadata blocks */
	if (dmz_locate_metadata(dev) < 0)
		return -1;

	if (dev->sb_version > 1) {
		int i;

		if (uuid_is_null(dev->uuid))
			uuid_generate_random(dev->uuid);
		for (i = 0; i < dev->nr_bdev; i++) {
			if (uuid_is_null(dev->bdev[i].uuid))
				uuid_generate_random(dev->bdev[i].uuid);
		}
	}

	dmz_get_label(dev, dev->label, false);

	if (dev->flags & DMZ_VERBOSE) {
		unsigned int nr_data_zones;

		printf("Format metadata %d:\n", dev->sb_version);
		if (dev->sb_version > 1) {
			char dev_uuid[UUID_STR_LEN];

			uuid_unparse(dev->uuid, dev_uuid);
			printf("  DM-Zoned UUID %s\n", dev_uuid);
			printf("  DM-Zoned Label %s\n", dev->label);
			for (i = 0; i < dev->nr_bdev; i++) {
				struct dmz_block_dev *bdev = &dev->bdev[i];
				char bdev_uuid[UUID_STR_LEN];

				uuid_unparse(bdev->uuid, bdev_uuid);
				printf("  Device %s UUID %s\n",
				       bdev->name, bdev_uuid);
				printf("  Device %s block offset %llu\n",
				       bdev->name, bdev->block_offset);
			}
		}
		printf("  %u useble zones\n",
		       dev->nr_usable_zones);
		printf("  Primary meta-data set: %u metadata blocks from block %llu (zone %u)\n",
		       dev->nr_meta_blocks,
		       dev->sb_block,
		       dmz_zone_id(dev, dev->sb_zone));
		printf("    Super block at block %llu and %llu\n",
		       dev->sb_block,
		       dev->sb_block + (dev->nr_meta_zones * dev->zone_nr_blocks));
		printf("    %u chunk mapping table blocks\n",
		       dev->nr_map_blocks);
		printf("    %u bitmap blocks\n",
		       dev->nr_bitmap_blocks);
		printf("    Using %u zones per meta-data set (%u total)\n",
		       dev->nr_meta_zones,
		       dev->total_nr_meta_zones);

		dev->nr_cache_zones -= dev->total_nr_meta_zones;
		nr_data_zones = dev->nr_usable_zones
			- (dev->total_nr_meta_zones + dev->nr_cache_zones +
			dev->nr_reserved_seq);
		printf("  %u data chunks capacity\n",
		       dev->nr_chunks);
		printf("    %u cache zone%s\n",
		       dev->nr_cache_zones,
		       dev->nr_cache_zones > 1 ? "s" : "");
		printf("    %u data zone%s\n",
		       nr_data_zones,
		       nr_data_zones > 1 ? "s" : "");
		printf("  %u sequential zone%s reserved for reclaim\n",
		       dev->nr_reserved_seq,
		       dev->nr_reserved_seq > 1 ? "s" : "");

	}

	/* Ready to write: first reset all zones */
	printf("Resetting sequential zones\n");
	if (dmz_reset_zones(dev) < 0)
		return -1;

	/* Write primary metadata set */
	printf("Writing primary metadata set\n");
	if (dmz_write_meta(dev, 0) < 0)
		return -1;

	/* Write secondary metadata set */
	printf("Writing secondary metadata set\n");
	if (dmz_write_meta(dev,
			   dev->zone_nr_blocks * dev->nr_meta_zones) < 0)
		return -1;

	if (dev->sb_version > 1 && dev->nr_bdev > 1) {
		printf("Writing tertiary metadata\n");
		for (i = 1; i < dev->nr_bdev; i++) {
			if (dmz_write_super(dev, 0,
					    dev->bdev[i].block_offset) < 0)
				return -1;
		}
	}

	if (dmz_sync_dev(dev))
		return -1;

	printf("Done.\n");

	return 0;
}

