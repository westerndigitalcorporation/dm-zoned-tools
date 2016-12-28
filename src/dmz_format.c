/*
 * This file is part of dm-zoned tools.
 *
 * Copyright (C) 2016, Western Digital.  All rights reserved.
 *
 * This software is distributed under the terms of the BSD 2-clause license,
 * "as is," without technical support, and WITHOUT ANY WARRANTY, without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. You should have received a copy of the BSD 2-clause license along
 * with dm-zoned tools.
 * If not, see <http://opensource.org/licenses/BSD-2-Clause>.
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
 * Determine metadata format and initialize meta zones.
 */
int dmz_write_super(struct dmz_dev *dev,
		    unsigned long long offset)
{
	unsigned long long sb_block = dev->sb_block + offset;
	struct dm_zoned_super *sb;
	__u64 gen = offset ? 0 : 1;
	__u32 crc;
	char *buf;
	int ret;

	printf("  Writing super block");

	buf = malloc(DMZ_BLOCK_SIZE);
	if (!buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}
	memset(buf, 0, DMZ_BLOCK_SIZE);

	sb = (struct dm_zoned_super *) buf;

	sb->magic = __cpu_to_le32(DMZ_MAGIC);
	sb->version = __cpu_to_le32(DMZ_META_VER);

	sb->gen = __cpu_to_le64(gen);

	sb->sb_block = __cpu_to_le64(sb_block);
	sb->nr_meta_blocks = __cpu_to_le32(dev->nr_meta_blocks);
	sb->nr_reserved_seq = __cpu_to_le32(dev->nr_reserved_seq);
	sb->nr_chunks = __cpu_to_le32(dev->nr_chunks);

	sb->nr_map_blocks = __cpu_to_le32(dev->nr_map_blocks);
	sb->nr_bitmap_blocks = __cpu_to_le32(dev->nr_bitmap_blocks);

	crc = dmz_crc32(gen, sb, DMZ_BLOCK_SIZE);
	sb->crc = __cpu_to_le32(crc);

	ret = dmz_write_block(dev, sb_block, buf);
	if (ret < 0)
		fprintf(stderr,
			"%s: Write super block at block %llu failed\n",
			dev->name,
			sb_block);

	free(buf);

	return ret;
}

static int dmz_write_mapping(struct dmz_dev *dev,
			     unsigned long long offset)
{
	unsigned long long map_block;
	struct dm_zoned_map *dmap;
	unsigned int i;
	char *buf;
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
				dev->name,
				map_block + i);
			break;
		}
	}

	free(buf);

	return ret;
}

static int dmz_write_bitmap(struct dmz_dev *dev,
			    unsigned long long offset)
{
	unsigned long long bitmap_block;
	unsigned int i;
	char *buf;
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
				dev->name,
				bitmap_block + i);
			break;
		}
	}

	free(buf);

	return ret;
}

static int dmz_write_meta(struct dmz_dev *dev,
			  unsigned long long offset)
{

	/* Write mapping table */
	if (dmz_write_mapping(dev, offset) < 0)
		return -1;

	/* Write bitmap blocks */
	if (dmz_write_bitmap(dev, offset) < 0)
		return -1;

	/* Write super block */
	if (dmz_write_super(dev, offset) < 0)
		return -1;

	return 0;
}

/*
 * Calculate location of metadata.
 */
int dmz_calulate_md_loc(struct dmz_dev *dev)
{
	struct blk_zone *zone;
	unsigned int i = 0;
	unsigned int nr_meta_blocks, nr_map_blocks;
	unsigned int nr_chunks, nr_meta_zones;
	unsigned int nr_bitmap_zones;

	dev->nr_active_zones = 0;
	dev->max_nr_meta_zones = 0;
	dev->last_meta_zone = 0;
	dev->nr_rnd_zones = 0;

	/* Count useable zones */
	for (i = 0; i < dev->nr_zones; i++) {

		zone = &dev->zones[i];

		if (dmz_zone_cond(zone) == BLK_ZONE_COND_READONLY) {
			printf("%s: Ignoring read-only zone %u\n",
			       dev->name,
			       dmz_zone_id(dev, zone));
			continue;
		}

		if (dmz_zone_cond(zone) == BLK_ZONE_COND_OFFLINE) {
			printf("%s: Ignoring offline zone %u\n",
			       dev->name,
			       dmz_zone_id(dev, zone));
			continue;
		}

		dev->nr_active_zones++;

		if (dmz_zone_rnd(zone)) {
			if (dev->sb_zone == NULL) {
				dev->sb_zone = zone;
				dev->last_meta_zone = i;
				dev->max_nr_meta_zones = 1;
			} else if (dev->last_meta_zone == (i - 1)) {
				dev->last_meta_zone = i;
				dev->max_nr_meta_zones++;
			}
			dev->nr_rnd_zones++;
		}

	}

	/*
	 * Randomly writeable zones are mandatory: at least 3
	 * (two for metadata and one for bufferring random writes).
	 */
	if (dev->nr_rnd_zones < 3) {
		fprintf(stderr,
			"%s: Not enough random zones found\n",
			dev->name);
		return -1;
	}

	/*
	 * It does not make sense to have more reserved
	 * sequential zones than random zones.
	 */
	if (dev->nr_reserved_seq > dev->nr_rnd_zones)
		dev->nr_reserved_seq = dev->nr_rnd_zones - 1;

	if (dev->nr_active_zones < (dev->nr_reserved_seq + 1)) {
		fprintf(stderr,
			"%s: Not enough useable zones found\n",
			dev->name);
		return -1;
	}


	assert(dev->sb_zone);
	dev->sb_block = dmz_sect2blk(dmz_zone_sector(dev->sb_zone));

	/*
	 * To facilitate addressing of the bitmap blocks, create
	 * one bitmap per zone, including meta zones and unuseable
	 * read-only and offline zones.
	 */
	dev->zone_nr_bitmap_blocks =
		dev->zone_nr_blocks >> (DMZ_BLOCK_SHIFT + 3);
	dev->nr_bitmap_blocks = dev->nr_zones * dev->zone_nr_bitmap_blocks;
	nr_bitmap_zones = (dev->nr_bitmap_blocks + dev->zone_nr_blocks - 1)
		/ dev->zone_nr_blocks;

	if (dev->nr_active_zones <= (nr_bitmap_zones + dev->nr_reserved_seq)) {
		fprintf(stderr,
			"%s: Not enough zones\n",
			dev->name);
		return -1;
	}

	/*
	 * Not counting the mapping table, the maximum number of chunks
	 * is the number of useable zones minus the bitmap zones and the
	 * number of reserved zones.
	 */
	nr_chunks = dev->nr_active_zones -
		(nr_bitmap_zones + dev->nr_reserved_seq);

	/* Assuming the maximum number of chunks, get the mapping table size */
	nr_map_blocks = nr_chunks / DMZ_MAP_ENTRIES;
	if (nr_chunks & DMZ_MAP_ENTRIES_MASK)
		nr_map_blocks++;

	/*
	 * And then a first estimate of the number of metadata zones
	 * (we need 2 sets of metadata).
	 */
	nr_meta_blocks = 1 + nr_map_blocks + dev->nr_bitmap_blocks;
	nr_meta_zones = ((nr_meta_blocks + dev->zone_nr_blocks - 1)
			 / dev->zone_nr_blocks);
	dev->total_nr_meta_zones = nr_meta_zones << 1;

	if (dev->total_nr_meta_zones > dev->nr_rnd_zones) {
		fprintf(stderr,
			"%s: Insufficient number of random zones "
			"(need %u, have %u)\n",
			dev->name,
			dev->total_nr_meta_zones,
			dev->nr_rnd_zones);
		return -1;
	}

	/*
	 * Now, fix the number of chunks and the mapping table size to
	 * make sure that everything fits on the drive.
	 */
	dev->nr_chunks = dev->nr_active_zones -
		(dev->total_nr_meta_zones + dev->nr_reserved_seq);
	dev->nr_map_blocks = dev->nr_chunks / DMZ_MAP_ENTRIES;
	if (dev->nr_chunks & DMZ_MAP_ENTRIES_MASK)
		dev->nr_map_blocks++;
	dev->map_block = dev->sb_block + 1;
	dev->bitmap_block = dev->map_block + dev->nr_map_blocks;

	dev->nr_meta_blocks = 1 + dev->nr_map_blocks + dev->nr_bitmap_blocks;
	dev->nr_meta_zones = ((dev->nr_meta_blocks + dev->zone_nr_blocks - 1)
			 / dev->zone_nr_blocks);
	dev->total_nr_meta_zones = dev->nr_meta_zones << 1;

	return 0;

}

/*
 * Format a device.
 */
int dmz_format(struct dmz_dev *dev)
{
	/*First, calculate location of the metadata blocks */
	if (dmz_calulate_md_loc(dev) < 0)
		return -1;

	if (dev->flags & DMZ_VERBOSE) {
		unsigned int nr_seq_data_zones;

		printf("Format:\n");
		printf("  %u metadata blocks from block %llu (zone %u)\n",
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
		printf("    Using %u zones for meta-data\n",
		       dev->total_nr_meta_zones);

		dev->nr_rnd_zones -= dev->total_nr_meta_zones;
		nr_seq_data_zones = dev->nr_active_zones
			- (dev->total_nr_meta_zones + dev->nr_rnd_zones +
			dev->nr_reserved_seq);
		printf("  %u chunks\n",
		       dev->nr_chunks);
		printf("    %u random data zone%s\n",
		       dev->nr_rnd_zones,
		       dev->nr_rnd_zones > 1 ? "s" : "");
		printf("    %u sequential data zone%s\n",
		       nr_seq_data_zones,
		       nr_seq_data_zones > 1 ? "s" : "");
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
	if (dmz_write_meta(dev, dev->zone_nr_blocks * dev->nr_meta_zones) < 0)
		return -1;

	/* Sync */
	printf("Syncing disk\n");
	if (fsync(dev->fd) < 0) {
		fprintf(stderr,
			"%s: fsync failed %d (%s)\n",
			dev->name,
			errno, strerror(errno));
		return -1;
	}

	printf("Done.\n");

	return 0;
}

