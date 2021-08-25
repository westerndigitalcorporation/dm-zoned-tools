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
#define dmz_plural(val)		((val> 1) ? "s" : "")
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

	if (dzone_id != DMZ_MAP_UNMAPPED) {
		/* This is a mapped chunk */
		mset->nr_mapped_chunks++;
		if (dzone_id >= dev->nr_zones) {
			dmz_err(dev, ind,
				"Chunk %u: invalid data zone %u\n",
				chunk, dzone_id);
			errors++;
			if (dmz_repair_dev(dev))
				dzone_id = DMZ_MAP_UNMAPPED;
		}
	}

	if (dzone_id == DMZ_MAP_UNMAPPED) {
		if (bzone_id != DMZ_MAP_UNMAPPED) {
			/* Unmapped chunk should not have a buffer zone */
			dmz_err(dev, ind,
				"Chunk %u: unmapped but buffer zone %u set\n",
				chunk, bzone_id);
			errors++;
			if (dmz_repair_dev(dev))
				bzone_id = DMZ_MAP_UNMAPPED;
		}
		goto out;
	}

	if (bzone_id == DMZ_MAP_UNMAPPED) {
		dzone = &dev->zones[dzone_id];
		if (dmz_zone_seq_req(dzone) && dmz_zone_empty(dzone)) {
			dmz_err(dev, ind,
				"Chunk %u: mapped to empty seq req zone %u\n",
				chunk, dzone_id);
			if (dmz_repair_dev(dev)) {
				/* Only count as error in repair mode */
				errors++;
				dzone_id = DMZ_MAP_UNMAPPED;
			}
		}
		goto out;
	}

	/* This is a mapped and buffered chunk */
	if (dzone_id < dev->nr_zones) {
		mset->nr_buf_chunks++;
		dzone = &dev->zones[dzone_id];
		if (dmz_zone_is_cache(dev, dzone)) {
			dmz_err(dev, ind,
				"Chunk %u: mapped to cache zone %u "
				"but using buffer zone %u\n",
				chunk, dzone_id, bzone_id);
			errors++;
			if (dmz_repair_dev(dev)) {
				bzone_id = DMZ_MAP_UNMAPPED;
				goto out;
			}
		}
	}

	if (bzone_id == dzone_id ||
	    bzone_id >= dev->nr_zones) {
		dmz_err(dev, ind,
			"Chunk %u: invalid buffer zone %u\n",
			chunk, dzone_id);
		errors++;
		if (dmz_repair_dev(dev))
			bzone_id = DMZ_MAP_UNMAPPED;
		goto out;
	}

	bzone = &dev->zones[bzone_id];
	if (!dmz_zone_is_cache(dev, bzone)) {
		dmz_err(dev, ind,
			"Chunk %u: buffer zone %u is not a cache zone\n",
			chunk, bzone_id);
		errors++;
		if (dmz_repair_dev(dev))
			bzone_id = DMZ_MAP_UNMAPPED;
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

	dmz_msg(dev, ind, "Checking data chunk mapping...\n");
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
		dmz_msg(dev, ind + 2,
			"No error: %u mapped chunk%s (%u buffered) checked\n",
			mset->nr_mapped_chunks,
			dmz_plural(mset->nr_mapped_chunks),
			mset->nr_buf_chunks);
		mset->flags |= DMZ_MSET_MAP_VALID;
		return 0;
	}

	dmz_err(dev, ind + 2,
		"%u error%s found: %u mapped chunk%s (%u buffered) checked\n",
		mset->error_count, dmz_plural(mset->error_count),
		mset->nr_mapped_chunks, dmz_plural(mset->nr_mapped_chunks),
		mset->nr_buf_chunks);

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
	unsigned int bad_bits = 0;
	int errors = 0;
	__u8 *buf;

	/* Read in the zone bitmap */
	ret = dmz_read_zone_bitmap(dev, mset, zone_id, &buf);
	if (ret != 0)
		return -1;

	for (b = 0; b < dev->zone_nr_blocks; b++) {
		if (!dmz_test_bit(buf, b))
			continue;
		bad_bits++;
		dmz_verr(dev, ind,
			 "Zone %u: unmapped zone but block %u valid\n",
			 zone_id, b);
		ind = 4;
		errors++;
		if (dmz_repair_dev(dev))
			dmz_clear_bit(buf, b);
	}

	if (bad_bits)
		dmz_verr(dev, ind,
			 "Zone %u: unmapped zone but %u block%s valid\n",
			 zone_id, bad_bits, dmz_plural(bad_bits));

	if (dmz_repair_dev(dev) && errors) {
		ret = dmz_write_zone_bitmap(dev, mset, zone_id, buf);
		if (ret != 0)
			goto out;
	}

	if (dmz_zone_seq_req(zone) && zone->wp != zone->start) {
		dmz_err(dev, ind,
			"Zone %u: unmapped sequential zone not empty "
			"(wp at +%u blocks)\n",
			zone_id,
			(unsigned int)dmz_sect2blk(zone->wp - zone->start));
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
 * Check the bitmap of an mapped zone: applies to only data zones all
 * blocks should be invalid.
 */
static int dmz_check_mapped_zone_bitmap(struct dmz_dev *dev,
					struct dmz_meta_set *mset,
					unsigned int chunk,
					struct blk_zone *zone,
					unsigned int bzone_id)
{
	unsigned int b, wp_block;
	int ret = 0, ind = 4;
	unsigned int dzone_id = dmz_zone_id(dev, zone);
	unsigned int dzone_weight = 0, bzone_weight = 0;
	unsigned int bad_bits;
	int errors = 0;
	__u8 *dbuf, *bbuf = NULL;

	/*
	 * Ignore buffer zones as they are checked
	 * together with the sequential data zone they buffer.
	 * Also ignore unbuffered data zones that are not sequential
	 * write required zones.
	 */
	if (dzone_id == bzone_id ||
	    (dmz_zone_is_cache(dev, zone) && (bzone_id == DMZ_MAP_UNMAPPED)))
		return 0;

	/* Read in the zone bitmap */
	ret = dmz_read_zone_bitmap(dev, mset, dzone_id, &dbuf);
	if (ret != 0)
		return -1;

	/* No valid block should be present after the write pointer */
	bad_bits = 0;
	wp_block = dmz_sect2blk(zone->wp - zone->start);
	for (b = 0; b < wp_block; b++) {
		if (dmz_test_bit(dbuf, b))
			dzone_weight++;
	}
	for (b = wp_block; b < dev->zone_nr_blocks; b++) {
		if (!dmz_test_bit(dbuf, b))
			continue;
		dmz_verr(dev, ind,
			 "Zone %u: block %u valid after zone wp block %u\n",
			 dzone_id, b, wp_block);
		dzone_weight++;
		bad_bits++;
		errors++;
		if (dmz_repair_dev(dev))
			dmz_clear_bit(dbuf, b);
	}

	if (bad_bits)
		dmz_err(dev, ind,
			"Zone %u: mapped to chunk %u, weight %u, "
			"%u block%s valid after zone wp block %u\n",
			dzone_id, chunk, dzone_weight,
			bad_bits, dmz_plural(bad_bits),
			wp_block);

	if (bzone_id != DMZ_MAP_UNMAPPED) {

		/* Read in the buffer zone bitmap */
		ret = dmz_read_zone_bitmap(dev, mset, bzone_id, &bbuf);
		if (ret != 0)
			goto out;

		bad_bits = 0;
		for (b = 0; b < wp_block; b++) {
			if (!dmz_test_bit(bbuf, b))
				continue;
			bzone_weight++;
			if (dmz_test_bit(dbuf, b)) {
				bad_bits++;
				dmz_verr(dev, ind,
					 "Zone %u: block %u valid in buffer "
					 "zone %u\n",
					 dzone_id, b, bzone_id);
				errors++;
				if (dmz_repair_dev(dev))
					dmz_clear_bit(dbuf, b);
			}
		}
		for (b = wp_block; b < dev->zone_nr_blocks; b++) {
			if (dmz_test_bit(bbuf, b))
				bzone_weight++;
		}

		if (bad_bits)
			dmz_err(dev, ind,
				"Zone %u: mapped to chunk %u, weight %u, "
				"%u valid block%s overlap with buffer zone %u "
				"(weight %u)\n",
				dzone_id, chunk, dzone_weight,
				bad_bits, dmz_plural(bad_bits),
				bzone_id,
				bzone_weight);

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
static unsigned int dmz_get_zone_mapping(struct dmz_dev *dev,
					 struct dmz_meta_set *mset,
					 struct blk_zone *zone,
					 unsigned int *bzone_id)
{
	unsigned int c, dzid, bzid;

	for (c = 0; c < dev->nr_chunks; c++) {
		dmz_get_chunk_mapping(dev, mset, c, &dzid, &bzid);
		if (dmz_zone_id(dev, zone) == dzid ||
		    dmz_zone_id(dev, zone) == bzid) {
			*bzone_id = bzid;
			return c;
		}
	}

	return DMZ_MAP_UNMAPPED;
}

static int dmz_check_bitmaps(struct dmz_dev *dev,
			     struct dmz_meta_set *mset)
{
	struct dmz_block_dev *bdev;
	struct blk_zone *zone;
	unsigned int chunk, bzone_id;
	unsigned int i, unmapped_zones = 0;
	unsigned int mapped_zones = 0;
	__u64 block = 0;
	int ind = 2;
	int ret;

	dmz_msg(dev, ind, "Checking zone bitmaps...\n");
	fflush(stdout);
	mset->error_count = 0;

	/*
	 * For mapped sequential zones, make sure that all valid blocks
	 * are before the zone write pointer position. If the zone is
	 * buffered, also check there is no valid block overlap between
	 * the sequential and buffer zones. For unmapped zones, check that
	 * the bitmap is empty, and that sequential zones are empty.
	 */
	for (i = 0; i < dev->nr_zones; i++) {

		zone = &dev->zones[i];
		bdev = dmz_zone_to_bdev(dev, zone);

		/*
		 * Skip the first zone of secoundary block devices as they
		 * only store the device super block.
		 */
		if (bdev->block_offset && block == bdev->block_offset) {
			block += dev->zone_nr_blocks;
			continue;
		}

		chunk = dmz_get_zone_mapping(dev, mset, zone, &bzone_id);

		if (chunk == DMZ_MAP_UNMAPPED) {
			ret = dmz_check_unmapped_zone_bitmap(dev, mset, zone);
			if (ret != 0)
				return -1;
			unmapped_zones++;
		} else {
			ret = dmz_check_mapped_zone_bitmap(dev, mset, chunk,
							   zone, bzone_id);
			if (ret != 0)
				return -1;
			mapped_zones++;
		}

		block += dev->zone_nr_blocks;
	}

	if (mset->error_count == 0) {
		dmz_msg(dev, ind + 2,
			"No error: %u unmapped zone%s + %u mapped zone%s "
			"checked\n",
			unmapped_zones, dmz_plural(unmapped_zones),
			mapped_zones, dmz_plural(mapped_zones));
		mset->flags |= DMZ_MSET_BITMAP_VALID;
		return 0;
	}

	dmz_msg(dev, ind + 2,
		"%u error%s found: %u unmapped zone%s + %u mapped zone%s "
		"checked\n",
		mset->error_count, (mset->error_count > 1) ? "s" : "",
		unmapped_zones, dmz_plural(unmapped_zones),
		mapped_zones, dmz_plural(mapped_zones));

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
		dmz_msg(dev, 2,
			"%s metadata set: %u error%s found%s\n",
			(mset->id == 0) ? "Primary" : "Secondary",
			mset->total_error_count,
			dmz_plural(mset->total_error_count),
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
		fprintf(stderr,
			"Read superblock %llu failed\n",
			mset->sb_block);
		return -1;
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
	if (__le32_to_cpu(sb->version) > DMZ_META_VER) {
		dmz_err(dev, 0,
			"invalid version (expected 0x%x, read 0x%x)\n",
			DMZ_META_VER, __le32_to_cpu(sb->version));
		goto err;
	}

	/* Check UUID for V2 metadata */
	if (__le32_to_cpu(sb->version) > 1) {
		__u64 bdev_sb_block;
		struct dmz_block_dev *bdev =
			dmz_block_to_bdev(dev, mset->sb_block, &bdev_sb_block);

		/* Check UUID */
		if (uuid_is_null(sb->dmz_uuid)) {
			dmz_err(dev, 0, "DM-Zoned UUID is null\n");
			goto err;
		}

		if (uuid_is_null(dev->uuid)) {
			uuid_copy(dev->uuid, sb->dmz_uuid);
		} else if (uuid_compare(sb->dmz_uuid, dev->uuid)) {
			char dev_uuid_buf[UUID_STR_LEN];
			char sb_uuid_buf[UUID_STR_LEN];

			uuid_unparse(dev->uuid, dev_uuid_buf);
			uuid_unparse(sb->dmz_uuid, sb_uuid_buf);
			dmz_err(dev, 0,
				"DM-Zoned UUID mismatch (expected %s, read %s)\n",
				dev_uuid_buf, sb_uuid_buf);
			goto err;
		}

		/* Check label */
		if (!strlen((const char *)sb->dmz_label)) {
			dmz_err(dev, 0, "DM-Zoned label is null\n");
			goto err;
		}

		if (!strlen(dev->label)) {
			memcpy(dev->label, (const char *)sb->dmz_label,
			       DMZ_LABEL_LEN);
		} else if (strncmp(dev->label, (const char *)sb->dmz_label,
				   DMZ_LABEL_LEN)) {
			dmz_err(dev, 0,
				"DM-Zoned label mismatch (expected %s, read %s)\n",
				dev->label, sb->dmz_label);
			goto err;
		}

		/* Check device UUID */
		if (uuid_is_null(sb->dev_uuid)) {
			dmz_err(dev, 0, "Device UUID is null\n");
			goto err;
		}

		uuid_copy(bdev->uuid, sb->dev_uuid);
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
	if (dev->nr_reserved_seq > dev->nr_cache_zones) {
		dmz_err(dev, 0,
			"invalid number of reserved sequential zones "
			"(expected less than %u, read %u)\n",
			dev->nr_cache_zones, dev->nr_reserved_seq);
		goto err;
	}

	/* Check the number of data chunks */
	dev->nr_meta_zones = DIV_ROUND_UP(__le64_to_cpu(sb->nr_meta_blocks),
					  dev->zone_nr_blocks);
	dev->nr_chunks = dev->nr_usable_zones -
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
			dev->nr_bitmap_blocks,
			__le32_to_cpu(sb->nr_bitmap_blocks));
		goto err;
	}

	/* OK */
	mset->gen = __le64_to_cpu(sb->gen);
	mset->flags |= DMZ_MSET_SB_VALID;
	mset->map_block = mset->sb_block + 1;
	mset->bitmap_block = mset->map_block + dev->nr_map_blocks;

	dmz_msg(dev, 0, "OK (version %d, generation %llu)\n",
		__le32_to_cpu(sb->version), mset->gen);

	return 0;

err:
	mset->total_error_count++;
	mset->flags &= ~DMZ_MSET_SB_VALID;

	return 0;
}

/*
 * Print format info.
 */
static void dmz_check_print_format(struct dmz_dev *dev,
				   int ind)
{
	unsigned int nr_data_zones;

	if (!(dev->flags & DMZ_VERBOSE))
		return;

	dmz_msg(dev, ind, "%u usable zones\n",
		dev->nr_usable_zones);
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

	dev->nr_cache_zones -= dev->total_nr_meta_zones;
	nr_data_zones = dev->nr_usable_zones
		- (dev->total_nr_meta_zones + dev->nr_cache_zones +
		   dev->nr_reserved_seq);
	dmz_msg(dev, ind, "%u data chunks capacity\n",
		dev->nr_chunks);
	dmz_msg(dev, ind + 2, "%u cache zone%s\n",
		dev->nr_cache_zones,
		dev->nr_cache_zones > 1 ? "s" : "");
	dmz_msg(dev, ind + 2, "%u data zone%s\n",
		nr_data_zones,
		nr_data_zones > 1 ? "s" : "");
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
					"Secondary super block found at "
					"block %llu\n",
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

static int dmz_check_tertiary_superblocks(struct dmz_dev *dev)
{
	int i;

	for (i = 1; i < dev->nr_bdev; i++) {
		struct dmz_meta_set mset;

		memset(&mset, 0, sizeof(mset));
		mset.id = i;
		mset.sb_block = dev->bdev[i].block_offset;
		dmz_msg(dev, 2,
			"Tertiary superblock at block %llu (zone %u)\n",
			mset.sb_block, dmz_block_zone_id(dev, mset.sb_block));
		if (dmz_check_sb(dev, &mset))
			return -1;
	}

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
 * Compare one metadata set against the other.
 */
static int dmz_compare_meta(struct dmz_dev *dev,
			    struct dmz_meta_set *check_mset,
			    struct dmz_meta_set *mset)
{
	int ret, ind = 2;
	unsigned int b;

	dmz_msg(dev, ind,
		"Validating %s metadata set against %s metadata set...\n",
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
			dmz_verr(dev, ind + 2,
				 "Block %llu differ\n",
				 mset->sb_block + b);
			mset->error_count++;
		}

	}

	if (mset->error_count == 0) {
		dmz_msg(dev, ind + 2,
			"No error: %u blocks checked\n",
			dev->nr_meta_blocks);
		mset->flags = DMZ_MSET_VALID;
	} else {
		dmz_err(dev, ind + 2,
			"%u block%s differ\n",
			mset->error_count, dmz_plural(mset->error_count));
		mset->total_error_count += mset->error_count;
	}

	return 0;
}

/*
 * Check a device metadata.
 */
int dmz_check(struct dmz_dev *dev)
{
	struct dmz_meta_set mset[3];
	struct dmz_meta_set *check_mset = NULL;
	int id, ret;

	/* Init */
	memset(mset, 0, sizeof(struct dmz_meta_set) * 3);
	mset[1].id = 1;
	mset[2].id = 2;
	mset[2].flags = DMZ_MSET_VALID;

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
				"%s metadata set generation differs: not "
				"checking\n",
				(id == 0) ? "Primary" : "Secondary");
		}

	}

	if (dmz_check_tertiary_superblocks(dev))
		mset[2].flags = 0;

	if (mset[0].flags == DMZ_MSET_VALID &&
	    mset[1].flags == DMZ_MSET_VALID &&
	    mset[2].flags == DMZ_MSET_VALID)
		dmz_msg(dev, 0,
			"No error detected\n");
	else
		dmz_msg(dev, 0,
			"Errors detected: running repair is recommended\n");

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
	struct dmz_meta_set mset[3];
	struct dmz_meta_set *check_mset = NULL;
	int id, ret;

	/* Init */
	memset(mset, 0, sizeof(struct dmz_meta_set) * 3);
	mset[1].id = 1;
	mset[2].id = 2;
	mset[2].flags = DMZ_MSET_VALID;
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
			"%u error%s found and repaired\n",
			check_mset->total_error_count,
			dmz_plural(check_mset->total_error_count));

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

	return dmz_sync_dev(dev);
}

/*
 * Change a device label.
 */
int dmz_relabel(struct dmz_dev *dev)
{
	struct dmz_meta_set mset[3];
	int i, ret;

	/* Init */
	memset(mset, 0, sizeof(struct dmz_meta_set) * 3);
	mset[1].id = 1;
	mset[2].id = 2;

	/* Check superblocks */
	ret = dmz_check_superblocks(dev, mset);
	if (ret != 0) {
		fprintf(stderr,
			"Check device superblocks failed\n");
		return -1;
	}

	ret = dmz_check_tertiary_superblocks(dev);
	if (ret == 0)
		mset[2].flags |= DMZ_MSET_VALID;

	if (!(mset[0].flags & DMZ_MSET_VALID) ||
	    !(mset[1].flags & DMZ_MSET_VALID) ||
	    !(mset[2].flags & DMZ_MSET_VALID))
		goto err;

	dmz_get_label(dev, dev->new_label, false);
	if (strcmp((char *)dev->label, dev->new_label) == 0) {
		printf("Device label already set to %s\n",
		       dev->new_label);
		return 0;
	}

	printf("Relabeling from %s to %s\n",
	       dev->label, dev->new_label);

	memcpy(dev->label, dev->new_label, DMZ_LABEL_LEN);

	/* Update primary super block */
	ret = dmz_write_super(dev, mset[0].gen, 0);
	if (ret) {
		fprintf(stderr, "Relabel primary super block failed\n");
		goto err;
	}

	/* Update primary super block */
	ret = dmz_write_super(dev, mset[1].gen,
			      dev->zone_nr_blocks * dev->nr_meta_zones);
	if (ret) {
		fprintf(stderr, "Relabel secondary super block failed\n");
		goto err;
	}

	if (dev->sb_version > 1 && dev->nr_bdev > 1) {
		/* Update tertiary super blocks */
		for (i = 1; i < dev->nr_bdev; i++) {
			ret = dmz_write_super(dev, 0,
					      dev->bdev[i].block_offset);
			if (ret) {
				fprintf(stderr,
					"Relabel tertiary super block failed\n");
				goto err;
			}
		}
	}

	if (dmz_sync_dev(dev))
		return -1;

	return 0;

err:
	dmz_msg(dev, 0, "Check and repair required\n");

	return -1;
}
