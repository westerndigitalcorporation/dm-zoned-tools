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
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <assert.h>
#include <asm/byteorder.h>

/*
 * Message macro.
 */
#define dmz_msg(dev,ind,format,args...)				\
	printf("%*s" format, ind, "", ## args)
#define dmz_err(dev,ind,format,args...)				\
	printf("%*s" format, ind, "", ## args)

#define dmz_verr(dev,ind,format,args...)			\
	do {							\
		if ((dev)->flags & DMZ_VERBOSE)			\
			printf("%*s" format, ind, "", ## args);	\
	} while (0)

/*
 * Test if we are running in repair mode.
 */
static inline int dmz_repair_dev(struct dmz_dev *dev)
{
	return dev->flags & DMZ_REPAIR;
}

/*
 * Read a zone bitmap blocks.
 */
static int dmz_read_zone_bitmap(struct dmz_dev *dev, struct dmz_meta_set *mset,
				unsigned int zone_id, __u8 **buf)
{
	__u8 *bitmap_buf;
	__u64 bitmap_block;
	unsigned int b;
	int ret;

	/* Allocate a buffer */
	bitmap_buf = calloc(dev->zone_nr_bitmap_blocks, DMZ_BLOCK_SIZE);
	if (!bitmap_buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}

	bitmap_block = mset->bitmap_block +
		(zone_id * dev->zone_nr_bitmap_blocks);
	for (b = 0; b < dev->zone_nr_bitmap_blocks; b++) {
		ret = dmz_read_block(dev, bitmap_block + b,
				     bitmap_buf + (b * DMZ_BLOCK_SIZE));
		if (ret != 0) {
			fprintf(stderr,
				"Read zone %u bitmap block %llu failed\n",
				zone_id, bitmap_block + b);
			free(bitmap_buf);
			return -1;
		}
	}

	*buf = bitmap_buf;

	return 0;
}

/*
 * Write a zone bitmap blocks.
 */
static int dmz_write_zone_bitmap(struct dmz_dev *dev, struct dmz_meta_set *mset,
				 unsigned int zone_id, __u8 *buf)
{
	__u64 bitmap_block;
	unsigned int b;
	int ret;

	bitmap_block = mset->bitmap_block +
		(zone_id * dev->zone_nr_bitmap_blocks);
	for (b = 0; b < dev->zone_nr_bitmap_blocks; b++) {
		ret = dmz_write_block(dev, bitmap_block + b,
				      buf + (b * DMZ_BLOCK_SIZE));
		if (ret != 0) {
			fprintf(stderr,
				"Write zone %u bitmap block %llu failed\n",
				zone_id, bitmap_block + b);
			return -1;
		}
	}

	return 0;
}

/*
 * Read a metadata set map table blocks.
 */
static int dmz_read_map_blocks(struct dmz_dev *dev, struct dmz_meta_set *mset)
{
	unsigned int b;
	int ret;

	/* Allocate a buffer */
	mset->map_buf = calloc(dev->nr_map_blocks, DMZ_BLOCK_SIZE);
	if (!mset->map_buf) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}

	for (b = 0; b < dev->nr_map_blocks; b++) {
		ret = dmz_read_block(dev, mset->map_block + b,
				     mset->map_buf + (b * DMZ_BLOCK_SIZE));
		if (ret != 0) {
			fprintf(stderr,
				"Read map block %llu failed\n",
				mset->map_block + b);
			free(mset->map_buf);
			mset->map_buf = NULL;
			return -1;
		}
	}

	return 0;
}

/*
 * Write a metadata set map table blocks.
 */
static int dmz_write_map_blocks(struct dmz_dev *dev, struct dmz_meta_set *mset)
{
	unsigned int b;
	int ret;

	for (b = 0; b < dev->nr_map_blocks; b++) {
		ret = dmz_write_block(dev, mset->map_block + b,
				      mset->map_buf + (b * DMZ_BLOCK_SIZE));
		if (ret != 0) {
			fprintf(stderr,
				"Write map block %llu failed\n",
				mset->map_block + b);
			return -1;
		}
	}

	return 0;
}

/*
 * Get a chunk mapping.
 */
static void dmz_get_chunk_mapping(struct dmz_dev *dev,
				  struct dmz_meta_set *mset,
				  unsigned int chunk,
				  unsigned int *dzone_id,
				  unsigned int *bzone_id)
{
	struct dm_zoned_map *map;
	unsigned int map_idx = chunk & DMZ_MAP_ENTRIES_MASK;

	map = (struct dm_zoned_map *)
		(mset->map_buf + ((chunk / DMZ_MAP_ENTRIES) * DMZ_BLOCK_SIZE));
	*dzone_id = __le32_to_cpu(map[map_idx].dzone_id);
	*bzone_id = __le32_to_cpu(map[map_idx].bzone_id);
}

/*
 * Set a chunk mapping.
 */
static void dmz_set_chunk_mapping(struct dmz_dev *dev,
				  struct dmz_meta_set *mset,
				  unsigned int chunk,
				  unsigned int dzone_id,
				  unsigned int bzone_id)
{
	struct dm_zoned_map *map;
	unsigned int map_idx = chunk & DMZ_MAP_ENTRIES_MASK;

	map = (struct dm_zoned_map *)
		(mset->map_buf + ((chunk / DMZ_MAP_ENTRIES) * DMZ_BLOCK_SIZE));
	map[map_idx].dzone_id = __cpu_to_le32(dzone_id);
	map[map_idx].bzone_id = __cpu_to_le32(bzone_id);
}

/*
 * Check that the zones mapping a chunk are not mapping other chunks.
 */
static int dmz_validate_chunk_mapping(struct dmz_dev *dev,
				      struct dmz_meta_set *mset,
				      unsigned int chunk,
				      unsigned int dzone_id,
				      unsigned int bzone_id)
{
	unsigned int c, dzid, bzid;
	unsigned int errors = 0;
	int ind = 4;

	if (dzone_id == DMZ_MAP_UNMAPPED)
		return 0;

	for (c = 0; c < dev->nr_chunks; c++) {

		if (c == chunk)
			continue;

		dmz_get_chunk_mapping(dev, mset, c, &dzid, &bzid);
		if (dzid ==  DMZ_MAP_UNMAPPED)
			continue;

		/* Check data zone */
		if (dzid == dzone_id ||
		    bzid == dzone_id) {
			dmz_err(dev, ind,
				"Chunk %u: data zone %u used by chunk %u\n",
				chunk, dzone_id, c);
			errors++;
			if (dmz_repair_dev(dev)) {
				dmz_set_chunk_mapping(dev, mset, c,
						      DMZ_MAP_UNMAPPED,
						      DMZ_MAP_UNMAPPED);
				continue;
			}
		}

		if (bzone_id == DMZ_MAP_UNMAPPED)
			continue;

		/* Check buffer zone */
		if (dzid == bzone_id ||
		    bzid == bzone_id) {
			dmz_err(dev, ind,
				"Chunk %u: buffer zone %u used by chunk %u\n",
				chunk, bzone_id, c);
			errors++;
			if (dmz_repair_dev(dev)) {
				dmz_set_chunk_mapping(dev, mset, c,
						      DMZ_MAP_UNMAPPED,
						      DMZ_MAP_UNMAPPED);
				continue;
			}
		}

	}

	return errors;
}

/*
 * Check a chunk mapping to zones.
 */
static int dmz_check_chunk_mapping(struct dmz_dev *dev,
				   struct dmz_meta_set *mset,
				   unsigned int chunk)
{
	unsigned int dzone_id, bzone_id;
	struct blk_zone *bzone, *dzone;
	unsigned int errors = 0;
	int ind = 4;

	dmz_get_chunk_mapping(dev, mset, chunk, &dzone_id, &bzone_id);

	if (dzone_id == DMZ_MAP_UNMAPPED) {
		/* Unmapped chunk: there should be no buffer zone */
		if (bzone_id != DMZ_MAP_UNMAPPED) {
			dmz_err(dev, ind,
				"Chunk %u: unmapped but buffer zone ID %u set\n",
				chunk, bzone_id);
			errors++;
			if (dmz_repair_dev(dev))
				bzone_id = DMZ_MAP_UNMAPPED;
		}
		goto out;
	}

	/* This is a mapped chunk */
	if (dzone_id >= dev->nr_zones) {
		dmz_err(dev, ind,
			"Chunk %u: invalid data zone ID %u\n",
			chunk, dzone_id);
		errors++;
		if (dmz_repair_dev(dev))
			dzone_id = DMZ_MAP_UNMAPPED;
	}

	if (bzone_id == DMZ_MAP_UNMAPPED)
		goto out;

	dzone = &dev->zones[dzone_id];
	if (dmz_zone_rnd(dzone)) {
		dmz_err(dev, ind,
			"Chunk %u: unexpected buffer zone ID %u\n",
			chunk, dzone_id);
		errors++;
		if (dmz_repair_dev(dev))
			bzone_id = DMZ_MAP_UNMAPPED;
	}

	/* This is a mapped and buffered chunk */
	if(bzone_id != DMZ_MAP_UNMAPPED) {
		if (bzone_id == dzone_id ||
		    bzone_id >= dev->nr_zones) {
			dmz_err(dev, ind,
				"Chunk %u: invalid buffer zone ID %u\n",
				chunk, dzone_id);
			errors++;
			if (dmz_repair_dev(dev))
				bzone_id = DMZ_MAP_UNMAPPED;
		}
	}

	if(bzone_id != DMZ_MAP_UNMAPPED) {
		bzone = &dev->zones[bzone_id];
		if (!dmz_zone_rnd(bzone)) {
			dmz_err(dev, ind,
				"Chunk %u: buffer zone %u is not a random zone\n",
				chunk, bzone_id);
			errors++;
			if (dmz_repair_dev(dev))
				bzone_id = DMZ_MAP_UNMAPPED;
		}
	}

out:
	if (dmz_repair_dev(dev) && errors)
		dmz_set_chunk_mapping(dev, mset, chunk,
				      dzone_id, bzone_id);

	errors += dmz_validate_chunk_mapping(dev, mset, chunk,
					     dzone_id, bzone_id);

	return errors;
}

/*
 * Check chunks mapping.
 */
static int dmz_check_mapping(struct dmz_dev *dev,
			     struct dmz_meta_set *mset)
{
	unsigned int chunk = 0;
	int ret, ind = 2;

	dmz_msg(dev, ind, "Checking data chunk mapping... ");
	fflush(stdout);

	mset->error_count = 0;

	/* Load mapping table */
	ret = dmz_read_map_blocks(dev, mset);
	if (ret != 0)
		return -1;

	/* First pass: check zone IDs validity */
	for (chunk = 0; chunk < dev->nr_chunks; chunk++)
		mset->error_count += dmz_check_chunk_mapping(dev, mset, chunk);

	if (mset->error_count == 0) {
		dmz_msg(dev, 0, "No error found\n");
		mset->flags |= DMZ_MSET_MAP_VALID;
		return 0;
	}

	dmz_msg(dev, 0,
		"%u error%s found (metadata block range %llu..%llu)\n",
		mset->error_count,
		(mset->error_count > 1) ? "s" : "",
		mset->map_block,
		mset->map_block + dev->nr_map_blocks - 1);

	if (dmz_repair_dev(dev)) {
		ret = dmz_write_map_blocks(dev, mset);
		if (ret != 0)
			return -1;
	}

	mset->total_error_count += mset->error_count;

	return 0;
}

/*
 * Check the bitmap of an unmapped zone: all blocks should be invalid.
 */
static int dmz_check_unmapped_zone_bitmap(struct dmz_dev *dev,
					  struct dmz_meta_set *mset,
					  struct blk_zone *zone)
{
	int ret = 0, ind = 4;
	unsigned int b, zone_id = dmz_zone_id(dev, zone);
	int errors = 0;
	__u8 *buf;

	/* Read in the zone bitmap */
	ret = dmz_read_zone_bitmap(dev, mset, zone_id, &buf);
	if (ret != 0)
		return -1;

	for (b = 0; b < dev->zone_nr_blocks; b++) {
		if (!dmz_test_bit(buf, b))
			continue;
		dmz_err(dev, ind,
			"Zone %u: unmapped zone, but block %u valid\n",
			zone_id, b);
		errors++;
		if (dmz_repair_dev(dev))
			dmz_clear_bit(buf, b);
	}

	if (dmz_repair_dev(dev) && errors) {
		ret = dmz_write_zone_bitmap(dev, mset, zone_id, buf);
		if (ret != 0)
			goto out;
	}

	if (dmz_zone_seq_req(zone) && zone->wp != zone->start) {
		dmz_err(dev, ind,
			"Zone %u: non-empty unmapped sequential zone\n",
			zone_id);
		errors++;
		if (dmz_repair_dev(dev))
			/* Reset zone */
			ret = dmz_reset_zone(dev, zone);
	}

out:
	mset->error_count += errors;
	free(buf);

	return ret;
}

/*
 * Check a sequential zone bitmap.
 */
static int dmz_check_seq_zone_bitmap(struct dmz_dev *dev,
				     struct dmz_meta_set *mset,
				     struct blk_zone *zone,
				     unsigned int bzone_id)
{
	unsigned int b, wp_block;
	int ret = 0, ind = 4;
	unsigned int dzone_id = dmz_zone_id(dev, zone);
	int errors = 0;
	__u8 *dbuf, *bbuf = NULL;

	/* Read in the zone bitmap */
	ret = dmz_read_zone_bitmap(dev, mset, dzone_id, &dbuf);
	if (ret != 0)
		return -1;

	/* No valid block should be present after the write pointer */
	wp_block = dmz_sect2blk(zone->wp - zone->start);
	for (b = wp_block; b < dev->zone_nr_blocks; b++) {
		if (!dmz_test_bit(dbuf, b))
			continue;
		dmz_err(dev, ind,
			"Zone %u: block %u valid after zone wp block %u\n",
			dzone_id, b, wp_block);
		errors++;
		if (dmz_repair_dev(dev))
			dmz_clear_bit(dbuf, b);
	}

	if (bzone_id != DMZ_MAP_UNMAPPED) {

		/* Read in the buffer zone bitmap */
		ret = dmz_read_zone_bitmap(dev, mset, dzone_id, &bbuf);
		if (ret != 0)
			goto out;

		for (b = 0; b < wp_block; b++) {
			if (dmz_test_bit(dbuf, b) && dmz_test_bit(bbuf, b)) {
				dmz_err(dev, ind,
					"Zone %u: block %u valid in buffer zone\n",
					dzone_id, b);
				errors++;
				if (dmz_repair_dev(dev))
					dmz_clear_bit(dbuf, b);
			}
		}

		free(bbuf);

	}

	mset->error_count += errors;

	if (dmz_repair_dev(dev) && errors) {
		ret = dmz_write_zone_bitmap(dev, mset, dzone_id, dbuf);
		if (ret != 0)
			ret = -1;
	}

out:
	free(dbuf);

	return ret;
}

/*
 * Get a zone mapping state and eventual buffer zone.
 */
static void dmz_get_zone_mapping(struct dmz_dev *dev, struct dmz_meta_set *mset,
				 struct blk_zone *zone, unsigned int *chunk,
				 unsigned int *bzone_id)
{
	unsigned int c, dzone_id;

	for (c = 0; c < dev->nr_chunks; c++) {
		dmz_get_chunk_mapping(dev, mset, c, &dzone_id, bzone_id);
		if (dzone_id == dmz_zone_id(dev, zone) ||
			*bzone_id == dmz_zone_id(dev, zone)) {
			*chunk = c;
			return;
		}
	}

	*chunk = DMZ_MAP_UNMAPPED;
	*bzone_id = DMZ_MAP_UNMAPPED;
}

static int dmz_check_bitmaps(struct dmz_dev *dev,
			     struct dmz_meta_set *mset)
{
	struct blk_zone *zone;
	unsigned int chunk, bzone_id;
	unsigned int i;
	int ret;

	dmz_msg(dev, 2, "Checking zone bitmaps... ");
	fflush(stdout);
	mset->error_count = 0;

	/*
	 * For mapped sequential zones, make sure that all valid are
	 * are before the zone write pointer and if the zone is
	 * buffered that there is no overlap of valid blocks with
	 * the buffer zone. For unmapped zones, check that the bitmap
	 * is empty, and that sequential zones are empty.
	 */
	for (i = 0; i < dev->nr_zones; i++) {

		zone = &dev->zones[i];
		dmz_get_zone_mapping(dev, mset, zone, &chunk, &bzone_id);

		if (chunk == DMZ_MAP_UNMAPPED) {
			ret = dmz_check_unmapped_zone_bitmap(dev, mset, zone);
			if (ret != 0)
				return -1;
			continue;
		}

		if (dmz_zone_seq_req(zone)) {
			ret = dmz_check_seq_zone_bitmap(dev, mset,
							zone, bzone_id);
			if (ret != 0)
				return -1;
		}

	}

	if (mset->error_count == 0) {
		dmz_msg(dev, 0, "No error found\n");
		mset->flags |= DMZ_MSET_BITMAP_VALID;
		return 0;
	}

	dmz_msg(dev, 0,
		"%u error%s found (metadata block range %llu..%llu)\n",
		mset->error_count,
		(mset->error_count > 1) ? "s" : "",
		mset->bitmap_block,
		mset->bitmap_block + dev->nr_bitmap_blocks - 1);

	mset->total_error_count += mset->error_count;

	return 0;
}

/*
 * Check metadata blocks of a meta set.
 */
static int dmz_check_meta(struct dmz_dev *dev,
			  struct dmz_meta_set *mset)
{
	int ret;

	/* Check zone mapping */
	ret = dmz_check_mapping(dev, mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check %s metadata set mapping failed\n",
			(mset->id == 0) ? "primary" : "secondary");
		return -1;
	}

	/* Check zone bitmap blocks */
	ret = dmz_check_bitmaps(dev, mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check %s metadata set zone bitmaps failed\n",
			(mset->id == 0) ? "primary" : "secondary");
		return -1;
	}

	if (mset->flags != DMZ_MSET_VALID)
		dmz_msg(dev, 0,
			"%s metadata set: %u error%s found%s\n",
			(mset->id == 0) ? "Primary" : "Secondary",
			mset->total_error_count,
			(mset->total_error_count > 1) ? "s" : "",
			dmz_repair_dev(dev) ? " and repaired" : "");

	return 0;
}

/*
 * Check the content of a super block
 */
static int dmz_check_sb(struct dmz_dev *dev, struct dmz_meta_set *mset)
{
	struct dm_zoned_super *sb = (struct dm_zoned_super *) mset->buf;
	__u32 stored_crc, calculated_crc;
	int ret, ind = 4;

	dmz_msg(dev, ind, "Checking super block... ");
	fflush(stdout);

	/* Read block */
	ret = dmz_read_block(dev, mset->sb_block, mset->buf);
	if (ret != 0) {
		/* Need a new line to end previous print out */
		dmz_msg(dev, 0, "\n");
		goto err;
	}

	/* Check magic */
	if (__le32_to_cpu(sb->magic) != DMZ_MAGIC) {
		dmz_err(dev, 0,
			"invalid magic (expected 0x%08x read 0x%08x)\n",
			DMZ_MAGIC, __le32_to_cpu(sb->magic));
		goto err;
	}

	/* Check CRC */
	stored_crc = __le32_to_cpu(sb->crc);
	sb->crc = 0;
	calculated_crc = dmz_crc32(sb->gen, mset->buf, DMZ_BLOCK_SIZE);
	if (calculated_crc != stored_crc) {
		dmz_err(dev, 0,
			"invalid crc (expected 0x%08x, read 0x%08x)\n",
			calculated_crc, stored_crc);
		goto err;
	}

	/* Check version */
	if (__le32_to_cpu(sb->version) != DMZ_META_VER) {
		dmz_err(dev, 0,
			"invalid version (expected 0x%x, read 0x%x)\n",
			DMZ_META_VER, __le32_to_cpu(sb->version));
		goto err;
	}

	/* Check location */
	if (__le64_to_cpu(sb->sb_block) != mset->sb_block) {
		dmz_err(dev, 0,
			"invalid location (expected %llu, read %llu)\n",
			mset->sb_block, __le64_to_cpu(sb->sb_block));
		goto err;
	}

	/* Check amount of metadata blocks */
	dev->nr_meta_blocks = 1 + __le32_to_cpu(sb->nr_map_blocks) +
		__le32_to_cpu(sb->nr_bitmap_blocks);
	if (__le64_to_cpu(sb->nr_meta_blocks) != dev->nr_meta_blocks) {
		dmz_err(dev, 0,
			"invalid number of metadata blocks "
			"(expected %u, read %llu)\n",
			dev->nr_meta_blocks, __le64_to_cpu(sb->nr_meta_blocks));
		goto err;
	}

	/* Check the number of reserved sequential zones */
	dev->nr_reserved_seq = __le32_to_cpu(sb->nr_reserved_seq);
	if (dev->nr_reserved_seq > dev->nr_rnd_zones) {
		dmz_err(dev, 0,
			"invalid number of reserved sequential zones "
			"(expected less than %u, read %u)\n",
			dev->nr_rnd_zones, dev->nr_reserved_seq);
		goto err;
	}

	/* Check the number of data chunks */
	dev->nr_meta_zones = DIV_ROUND_UP(__le64_to_cpu(sb->nr_meta_blocks),
					  dev->zone_nr_blocks);
	dev->nr_chunks = dev->nr_useable_zones -
		((dev->nr_meta_zones * 2) + dev->nr_reserved_seq);
	if (__le32_to_cpu(sb->nr_chunks) != dev->nr_chunks) {
		dmz_err(dev, 0,
			"invalid number of chunks "
			"(expected %u, read %u)\n",
			dev->nr_chunks, __le32_to_cpu(sb->nr_chunks));
		goto err;
	}

	/* Check number of map blocks */
	dev->nr_map_blocks = DIV_ROUND_UP(dev->nr_chunks, DMZ_MAP_ENTRIES);
	if (__le32_to_cpu(sb->nr_map_blocks) != dev->nr_map_blocks) {
		dmz_err(dev, 0,
			"invalid number of map blocks "
			"(expected %u, read %u)\n",
			dev->nr_map_blocks, __le32_to_cpu(sb->nr_map_blocks));
		goto err;
	}

	/* Check the number of zone bitmap blocks */
	dev->nr_bitmap_blocks = dev->nr_zones * dev->zone_nr_bitmap_blocks;
	if (__le32_to_cpu(sb->nr_bitmap_blocks) != dev->nr_bitmap_blocks) {
		dmz_err(dev, 0,
			"invalid number of zone bitmap blocks "
			"(expected %u, read %u)\n",
			dev->nr_bitmap_blocks, __le32_to_cpu(sb->nr_bitmap_blocks));
		goto err;
	}

	/* OK */
	mset->gen = __le64_to_cpu(sb->gen);
	mset->flags |= DMZ_MSET_SB_VALID;
	mset->map_block = mset->sb_block + 1;
	mset->bitmap_block = mset->map_block + dev->nr_map_blocks;

	dmz_msg(dev, 0, "OK (generation %llu)\n", mset->gen);

	return 0;

err:
	mset->total_error_count++;
	return 0;
}

/*
 * Print format info.
 */
static void dmz_check_print_format(struct dmz_dev *dev,
				   int ind)
{
	unsigned int nr_seq_data_zones;

	if (!(dev->flags & DMZ_VERBOSE))
		return;

	dmz_msg(dev, ind, "%u useable zones\n",
		dev->nr_useable_zones);
	dmz_msg(dev, ind, "%u metadata blocks per set\n",
		dev->nr_meta_blocks);
	dmz_msg(dev, ind + 2, "Super block at block %llu and %llu\n",
		dev->sb_block,
		dev->sb_block + (dev->nr_meta_zones * dev->zone_nr_blocks));
	dmz_msg(dev, ind + 2, "%u chunk mapping table blocks\n",
		dev->nr_map_blocks);
	dmz_msg(dev, ind + 2, "%u bitmap blocks\n",
		dev->nr_bitmap_blocks);
	dmz_msg(dev, ind + 2, "Using %u zones per meta-data set (%u total)\n",
		dev->nr_meta_zones,
		dev->total_nr_meta_zones);

	dev->nr_rnd_zones -= dev->total_nr_meta_zones;
	nr_seq_data_zones = dev->nr_useable_zones
		- (dev->total_nr_meta_zones + dev->nr_rnd_zones +
		   dev->nr_reserved_seq);
	dmz_msg(dev, ind, "%u data chunks capacity\n",
		dev->nr_chunks);
	dmz_msg(dev, ind + 2, "%u random zone%s\n",
		dev->nr_rnd_zones,
		dev->nr_rnd_zones > 1 ? "s" : "");
	dmz_msg(dev, ind + 2, "%u sequential zone%s\n",
		nr_seq_data_zones,
		nr_seq_data_zones > 1 ? "s" : "");
	dmz_msg(dev, ind, "%u sequential zone%s reserved for reclaim\n",
		dev->nr_reserved_seq,
		dev->nr_reserved_seq > 1 ? "s" : "");
}

/*
 * Test if a block is a super block.
 */
static int dmz_block_is_sb(__u8 *buf)
{
	struct dm_zoned_super *sb = (struct dm_zoned_super *) buf;

	return __le32_to_cpu(sb->magic) == DMZ_MAGIC;
}

/*
 * Check validity of the device superblocks.
 */
static int dmz_check_superblocks(struct dmz_dev *dev,
				 struct dmz_meta_set *mset)
{
	unsigned int i;
	int ret, ind = 2;

	/* Calculate metadata location */
	dmz_msg(dev, 0, "Locating metadata...\n");
	if (dmz_locate_metadata(dev) < 0) {
		fprintf(stderr,
			"Failed to locate metadata\n");
		return -1;
	}

	/* Check primary super block */
	dmz_msg(dev, ind, "Primary metadata set at block %llu (zone %u)\n",
	       dev->sb_block, dmz_zone_id(dev, dev->sb_zone));

	mset[0].sb_block = dev->sb_block;
	ret = dmz_check_sb(dev, &mset[0]);
	if (ret != 0)
		return -1;

	if (mset[0].flags & DMZ_MSET_SB_VALID) {

		dmz_check_print_format(dev, ind + 2);

		/* Secondary super block follows the primary metadata set */
		mset[1].sb_block = mset[0].sb_block
			+ (dev->nr_meta_zones * dev->zone_nr_blocks);

	} else {

		/* Find secondary super block */
		dmz_err(dev, ind + 2,
			"Super block invalid: locating secondary super block\n");
		mset[1].sb_block = mset[0].sb_block + dev->zone_nr_blocks;
		for (i = 0; i < dev->max_nr_meta_zones - 1; i++) {
			ret = dmz_read_block(dev, mset[1].sb_block,
					     mset[1].buf);
			if (ret != 0)
				continue;
			if (dmz_block_is_sb(mset[1].buf)) {
				dmz_msg(dev, ind + 2,
					"Secondary super block found at block %llu\n",
					mset[1].sb_block);
				break;
			}
			mset[1].sb_block += dev->zone_nr_blocks;
		}
		if (i >= dev->max_nr_meta_zones) {
			dmz_err(dev, ind, "Secondary super block not found\n");
			return -1;
		}
	}

	/* Check secondary super block */
	dmz_msg(dev, ind,
		"Secondary metadata set at block %llu (zone %u)\n",
		mset[1].sb_block, dmz_block_zone_id(dev, mset[1].sb_block));

	ret = dmz_check_sb(dev, &mset[1]);
	if (ret != 0)
		return -1;

	if (mset[1].flags & DMZ_MSET_SB_VALID &&
	    !(mset[0].flags & DMZ_MSET_SB_VALID))
		dmz_check_print_format(dev, ind + 2);

	return 0;
}

/*
 * Choose a valid metadata set for checks. Here valid means that
 * the set super block has no error AND has the highest generation.
 */
static struct dmz_meta_set *dmz_validate_meta_set(struct dmz_dev *dev,
						  struct dmz_meta_set *mset)
{
	int valid = 0;

	if ((mset[0].flags & DMZ_MSET_SB_VALID) &&
	    (mset[1].flags & DMZ_MSET_SB_VALID)) {
		if (mset[0].gen < mset[1].gen)
			valid = 1;
		else
			valid = 0;
	} else if (mset[0].flags & DMZ_MSET_SB_VALID) {
		valid = 0;
	} else if (mset[1].flags & DMZ_MSET_SB_VALID) {
		valid = 1;
	} else {
		dmz_err(dev, 2, "No valid superblock found\n");
		return NULL;
	}

	return &mset[valid];
}

/*
 * Comapre one metadata set against the other.
 */
static int dmz_compare_meta(struct dmz_dev *dev,
			    struct dmz_meta_set *check_mset,
			    struct dmz_meta_set *mset)
{
	int ret, ind = 2;
	unsigned int b;

	dmz_msg(dev, ind,
		"Validating %s metadata set against %s metadata set... ",
		(mset->id == 0) ? "primary" : "secondary",
		(check_mset->id == 0) ? "primary" : "secondary");
	fflush(stdout);

	mset->error_count = 0;

	/* Compare blocks (skip the super block) */
	for(b = 1; b < dev->nr_meta_blocks; b++) {

		ret = dmz_read_block(dev, check_mset->sb_block + b,
				     check_mset->buf);
		if (ret != 0)
			return -1;

		ret = dmz_read_block(dev, mset->sb_block + b, mset->buf);
		if (ret != 0)
			return -1;

		if (memcmp(check_mset->buf, mset->buf, DMZ_BLOCK_SIZE) != 0) {
			dmz_err(dev, ind + 2,
				"%sBlock %llu differ\n",
				(mset->error_count == 0) ? "\n" : "",
				mset->sb_block + b);
			mset->error_count++;
		}

	}

	if (mset->error_count == 0) {
		printf("No error found\n");
		mset->flags = DMZ_MSET_VALID;
	} else {
		mset->total_error_count += mset->error_count;
	}

	return 0;
}

/*
 * Check a device metadata.
 */
int dmz_check(struct dmz_dev *dev)
{
	struct dmz_meta_set mset[2];
	struct dmz_meta_set *check_mset = NULL;
	int id, ret;

	/* Init */
	memset(mset, 0, sizeof(struct dmz_meta_set) * 2);
	mset[1].id = 1;

	/* Check */
	ret = dmz_check_superblocks(dev, mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check device superblocks failed\n");
		return -1;
	}

	check_mset = dmz_validate_meta_set(dev, mset);
	if (!check_mset)
		return -1;

	dmz_msg(dev, 0, "Checking %s metadata set\n",
		(check_mset->id == 0) ? "primary" : "secondary");

	ret = dmz_check_meta(dev, check_mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check %s metadata set failed\n",
			(check_mset->id == 0) ? "primary" : "secondary");
		ret = -1;
		goto out;
	}

	id = (check_mset->id + 1) % 2;
	if (mset[id].flags & DMZ_MSET_SB_VALID) {

		if (mset[id].gen == check_mset->gen) {
			ret = dmz_compare_meta(dev, check_mset, &mset[id]);
			if (ret != 0) {
				fprintf(stderr,
					"Check %s metadata set failed\n",
					(id == 0) ? "primary" : "secondary");
				ret = -1;
				goto out;
			}
		} else {
			dmz_msg(dev, 0,
				"%s metadata set generation differs: not checking\n",
				(id == 0) ? "Primary" : "Secondary");
		}

	}

	if (mset[0].flags == DMZ_MSET_VALID &&
	    mset[1].flags == DMZ_MSET_VALID)
		dmz_msg(dev, 0, "Done\n");
	else
		dmz_msg(dev, 0, "Running repair is recommended\n");

out:
	free(mset[0].map_buf);
	free(mset[1].map_buf);

	return ret;
}

/*
 * Copy one metadata set to the other.
 */
static int dmz_repair_sync_meta(struct dmz_dev *dev,
				struct dmz_meta_set *src_mset,
				struct dmz_meta_set *dst_mset)
{
	__u8 *buf = src_mset->buf;
	__u64 dst_sb_offset = 0;
	unsigned int b;
	int ret;

	if (dst_mset->flags == DMZ_MSET_VALID &&
	    src_mset->gen == dst_mset->gen)
		/* Nothing to do */
		return 0;

	dmz_msg(dev, 0,
		"Syncing %s metadata set to %s metadata set...\n",
		(src_mset->id == 0) ? "primary" : "secondary",
		(dst_mset->id == 0) ? "primary" : "secondary");

	/* Write super block in destination */
	if (dst_mset->id != 0)
		dst_sb_offset = dev->zone_nr_blocks * dev->nr_meta_zones;
	ret = dmz_write_super(dev, src_mset->gen, dst_sb_offset);
	if (ret != 0)
		return -1;

	/* Copy blocks (using the super block buffer) */
	for(b = 1; b < dev->nr_meta_blocks; b++) {

		ret = dmz_read_block(dev, src_mset->sb_block + b, buf);
		if (ret != 0)
			return -1;

		ret = dmz_write_block(dev, dst_mset->sb_block + b, buf);
		if (ret != 0)
			return -1;

	}

	return 0;
}

/*
 * Check and repair a device metadata.
 */
int dmz_repair(struct dmz_dev *dev)
{
	struct dmz_meta_set mset[2];
	struct dmz_meta_set *check_mset = NULL;
	int id, ret;

	/* Init */
	memset(mset, 0, sizeof(struct dmz_meta_set) * 2);
	mset[1].id = 1;
	dev->flags |= DMZ_REPAIR;

	/* Check */
	ret = dmz_check_superblocks(dev, mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check device superblocks failed\n");
		return -1;
	}

	check_mset = dmz_validate_meta_set(dev, mset);
	if (!check_mset)
		return -1;

	dmz_msg(dev, 0,
		"Using %s metadata set for checks\n",
		(check_mset->id == 0) ? "primary" : "secondary");

	ret = dmz_check_meta(dev, check_mset);
	free(check_mset->map_buf);

	if (ret != 0) {
		fprintf(stderr,
			"Check %s metadata set failed\n",
			(check_mset->id == 0) ? "primary" : "secondary");
		return -1;
	}

	if (check_mset->total_error_count)
		/* Errors found and fixed: sync metadata sets */
		dmz_msg(dev, 0,
			"%u errors found and repaired\n",
			check_mset->total_error_count);

	/*
	 * If errors where found, we need to fix also the other metadata set.
	 * We also need to sync the metadata sets if the generations are
	 * different, even if no error was found.
	 */
	if (check_mset->id == 0)
		id = 1;
	else
		id = 0;
	ret = dmz_repair_sync_meta(dev, check_mset, &mset[id]);
	if (ret != 0) {
		fprintf(stderr,
			"Sync %s metadata set to %s metadata set failed\n",
			(check_mset->id == 0) ? "primary" : "secondary",
			(id == 0) ? "primary" : "secondary");
		return -1;
	}

	/* Sync device */
	if (dmz_sync_dev(dev) < 0)
		return -1;

	return 0;
}

