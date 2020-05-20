/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of dm-zoned tools.
 * Copyright (C) 2016, Western Digital. All rights reserved.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Damien Le Moal (damien.lemoal@wdc.com)
 */
#ifndef __DMZ_H__
#define __DMZ_H__

#define _LARGEFILE64_SOURCE

#include "config.h"

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/blkzoned.h>
#include <uuid/uuid.h>

/* Unknown block zone type */
#define BLK_ZONE_TYPE_UNKNOWN	0

/*
 * Metadata version.
 */
#define DMZ_META_VER	2

/*
 * On-disk super block magic.
 */
#define DMZ_MAGIC	((((unsigned int)('D')) << 24) | \
			 (((unsigned int)('Z')) << 16) | \
			 (((unsigned int)('B')) <<  8) | \
			 ((unsigned int)('D')))

/*
 * On disk super block.
 * This uses a full 4KB block. This block is followed on disk
 * by the chunk mapping table to zones and the bitmap blocks
 * indicating block validity.
 * The overall resulting metadat format is:
 *    (1) Super block (1 block)
 *    (2) Chunk mapping table (nr_map_blocks)
 *    (3) Bitmap blocks (nr_bitmap_blocks)
 * with all blocks stored in consecutive random zones starting
 * from the first random zone found on disk.
 */
struct dm_zoned_super {

	/* Magic number */
	__le32		magic;			/*   4 */

	/* Metadata version number */
	__le32		version;		/*   8 */

	/* Generation number */
	__le64		gen;			/*  16 */

	/* This block number */
	__le64		sb_block;		/*  24 */

	/* The number of metadata blocks, including this super block */
	__le32		nr_meta_blocks;		/*  28 */

	/* The number of sequential zones reserved for reclaim */
	__le32		nr_reserved_seq;	/*  32 */

	/* The number of entries in the mapping table */
	__le32		nr_chunks;		/*  36 */

	/* The number of blocks used for the chunk mapping table */
	__le32		nr_map_blocks;		/*  40 */

	/* The number of blocks used for the block bitmaps */
	__le32		nr_bitmap_blocks;	/*  44 */

	/* Checksum */
	__le32		crc;			/*  48 */

	/* Fields added by Metadata version 2 */
	/* DM-Zoned label */
	__u8		dmz_label[32];		/*  80 */

	/* DM-Zoned UUID */
	__u8		dmz_uuid[16];		/*  96 */

	/* Device UUID */
	__u8		dev_uuid[16];		/*  112 */

	/* Padding to full 512B sector */
	__u8		reserved[400];		/* 512 */

} __attribute__ ((packed));

/*
 * Chunk mapping entry: entries are indexed by chunk number
 * and give the zone ID (dzone_id) mapping the chunk. This zone
 * may be sequential or random. If it is a sequential zone,
 * a second zone (bzone_id) used as a write buffer may also be
 * specified. This second zone will always be a random zone.
 */
struct dm_zoned_map {
	__le32		dzone_id;
	__le32		bzone_id;
} __attribute__ ((packed));

/*
 * dm-zoned creates 4KB block size devices, always.
 */
#define DMZ_BLOCK_SHIFT		12
#define DMZ_BLOCK_SIZE		(1 << DMZ_BLOCK_SHIFT)
#define DMZ_BLOCK_MASK		(DMZ_BLOCK_SIZE - 1)

#define DMZ_BLOCK_SHIFT_BITS	(DMZ_BLOCK_SHIFT + 3)
#define DMZ_BLOCK_SIZE_BITS	(DMZ_BLOCK_SIZE << 3)
#define DMZ_BLOCK_MASK_BITS	(DMZ_BLOCK_SIZE_BITS - 1)

#define DMZ_BLOCK_SECTORS_SHIFT	(DMZ_BLOCK_SHIFT - 9)
#define DMZ_BLOCK_SECTORS	(DMZ_BLOCK_SIZE >> 9)
#define DMZ_BLOCK_SECTORS_MASK	(DMZ_BLOCK_SECTORS - 1)

#define dmz_blk2sect(b)		((b) << DMZ_BLOCK_SECTORS_SHIFT)
#define dmz_sect2blk(s)		((s) >> DMZ_BLOCK_SECTORS_SHIFT)

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

/*
 * Chunk mapping table metadata: 512 8-bytes entries per 4KB block.
 */
#define DMZ_MAP_ENTRIES		(DMZ_BLOCK_SIZE / sizeof(struct dm_zoned_map))
#define DMZ_MAP_ENTRIES_MASK	(DMZ_MAP_ENTRIES - 1)
#define DMZ_MAP_UNMAPPED	UINT_MAX

/*
 * Default number of sequential zones reserved for reclaim.
 */
#define DMZ_NR_RESERVED_SEQ	16

/*
 * Device types.
 */
enum dmz_dev_type {
	DMZ_TYPE_ZONED_HA = 1,
	DMZ_TYPE_ZONED_HM,
	DMZ_TYPE_REGULAR,
};

/*
 * Device flags.
 */
#define DMZ_VERBOSE		0x00000001
#define DMZ_VVERBOSE		0x00000002
#define DMZ_REPAIR		0x00000004
#define DMZ_OVERWRITE		0x00000008
#define DMZ_CACHE		0x00000010

/*
 * Operations.
 */
enum dmz_op {
	DMZ_OP_FORMAT = 1,
	DMZ_OP_CHECK,
	DMZ_OP_REPAIR,
	DMZ_OP_START,
	DMZ_OP_STOP,
};

/*
 * Block device descriptor.
 */
struct dmz_block_dev {
	char		*path;
	char		*name;

	enum dmz_dev_type type;

	uuid_t		uuid;
	__u64		capacity;

	__u64		block_offset;

	size_t		zone_nr_sectors;
	size_t		zone_nr_blocks;

	int		nr_zones;

	int		fd;
};

/*
 * Device descriptor.
 */
struct dmz_dev {

	/* Device block devices */
	struct dmz_block_dev bdev[2];
	int		op;
	unsigned int	flags;
	char		label[32];
	uuid_t		uuid;

	/* Device info */
	__u64		capacity;

	unsigned int	nr_zones;
	unsigned int	nr_meta_zones;
	unsigned int	nr_meta_blocks;
	unsigned int	nr_reserved_seq;
	unsigned int	nr_chunks;
	unsigned int	nr_usable_zones;
	unsigned int	max_nr_meta_zones;
	unsigned int	last_meta_zone;
	unsigned int	total_nr_meta_zones;
	unsigned int	nr_cache_zones;

	struct blk_zone	*zones;

	size_t		zone_nr_sectors;
	size_t		zone_nr_blocks;

	/* First metadata zone */
	unsigned int	sb_version;
	struct blk_zone	*sb_zone;
	__u64		sb_block;

	/* Zone bitmaps */
	size_t		zone_nr_bitmap_blocks;
	unsigned int	nr_bitmap_blocks;
	__u64		bitmap_block;

	/* Mapping table */
	unsigned int	nr_map_blocks;
	__u64		map_block;

};

/*
 * In-memory representation of a metadata set.
 */
struct dmz_meta_set {

	int		id;
	unsigned int	flags;

	__u64		sb_block;
	__u64		map_block;
	__u64		bitmap_block;

	__u8		buf[DMZ_BLOCK_SIZE];
	__u8		*map_buf;

	__u64		gen;

	unsigned int	nr_mapped_chunks;
	unsigned int	nr_buf_chunks;

	unsigned int	error_count;
	unsigned int	total_error_count;

};

/*
 * Bitmap operations.
 */
static inline int dmz_test_bit(__u8 *bitmap,
			       unsigned int bit)
{
	return bitmap[bit >> 3] & (1 << (bit & 0x7));
}
static inline void dmz_set_bit(__u8 *bitmap,
			       unsigned int bit)
{
	bitmap[bit >> 3] |= 1 << (bit & 0x7);
}
static inline void dmz_clear_bit(__u8 *bitmap,
				 unsigned int bit)
{
	bitmap[bit >> 3] &= ~(1 << (bit & 0x7));
}

/*
 * Metadata set flags.
 */
#define DMZ_MSET_SB_VALID	0x00000001
#define DMZ_MSET_MAP_VALID	0x00000002
#define DMZ_MSET_BITMAP_VALID	0x00000004
#define DMZ_MSET_VALID		(DMZ_MSET_SB_VALID |  \
				 DMZ_MSET_MAP_VALID |	\
				 DMZ_MSET_BITMAP_VALID)

#define dmz_bdev_is_ha(bdev)	((bdev)->type == DMZ_TYPE_ZONED_HA)
#define dmz_bdev_is_hm(bdev)	((bdev)->type == DMZ_TYPE_ZONED_HM)
#define dmz_bdev_is_zoned(bdev)	(dmz_bdev_is_ha(bdev) || dmz_bdev_is_hm(bdev))

#define dmz_zone_type(z)	(z)->type
#define dmz_zone_unknown(z)	((z)->type == BLK_ZONE_TYPE_UNKNOWN)
#define dmz_zone_conv(z)	((z)->type == BLK_ZONE_TYPE_CONVENTIONAL)
#define dmz_zone_seq_req(z)	((z)->type == BLK_ZONE_TYPE_SEQWRITE_REQ)
#define dmz_zone_seq_pref(z)	((z)->type == BLK_ZONE_TYPE_SEQWRITE_PREF)
#define dmz_zone_rnd(z)		(dmz_zone_conv(z) || dmz_zone_seq_pref(z))

static inline bool dmz_zone_is_cache(struct dmz_dev *dev, struct blk_zone *zone)
{
	if (dev->bdev[1].name)
		return dmz_zone_unknown(zone);
	return dmz_zone_rnd(zone);
}

static inline const char *dmz_zone_type_str(struct blk_zone *zone)
{
	switch (dmz_zone_type(zone)) {
	case BLK_ZONE_TYPE_CONVENTIONAL:
		return( "Conventional" );
	case BLK_ZONE_TYPE_SEQWRITE_REQ:
		return( "Sequential-write-required" );
	case BLK_ZONE_TYPE_SEQWRITE_PREF:
		return( "Sequential-write-preferred" );
	}
	return( "Unknown-type" );
}

#define dmz_zone_cond(z)	(z)->cond

static inline const char *dmz_zone_cond_str(struct blk_zone *zone)
{
	switch (dmz_zone_cond(zone)) {
	case BLK_ZONE_COND_NOT_WP:
		return "Not-write-pointer";
	case BLK_ZONE_COND_EMPTY:
		return "Empty";
	case BLK_ZONE_COND_IMP_OPEN:
		return "Implicit-open";
	case BLK_ZONE_COND_EXP_OPEN:
		return "Explicit-open";
	case BLK_ZONE_COND_CLOSED:
		return "Closed";
	case BLK_ZONE_COND_READONLY:
		return "Read-only";
	case BLK_ZONE_COND_FULL:
		return "Full";
	case BLK_ZONE_COND_OFFLINE:
		return "Offline";
	}
	return "Unknown-condition";
}

#define dmz_zone_empty(z)	(dmz_zone_cond(z) == BLK_ZONE_COND_EMPTY)

#define dmz_zone_sector(z)	(z)->start
#define dmz_zone_id(dev, zone)	((unsigned int)(dmz_zone_sector(zone) / (dev)->zone_nr_sectors))
#define dmz_zone_length(z)	(z)->len
#define dmz_zone_wp_sector(z)	(z)->wp
#define dmz_zone_need_reset(z)	(int)(z)->reset
#define dmz_zone_non_seq(z)	(int)(z)->non_seq

extern unsigned int dmz_block_zone_id(struct dmz_dev *dev, __u64 block);
extern int dmz_open_dev(struct dmz_block_dev *dev, enum dmz_op op, int flags);
extern void dmz_close_dev(struct dmz_block_dev *dev);
extern int dmz_get_dev_holder(struct dmz_block_dev *dev, char *holder);
extern int dmz_sync_dev(struct dmz_block_dev *dev);
extern int dmz_get_dev_zones(struct dmz_dev *dev);
extern struct dmz_block_dev *dmz_zone_to_bdev(struct dmz_dev *dev,
					      struct blk_zone *zone);
extern int dmz_reset_zone(struct dmz_dev *dev, struct blk_zone *zone);
extern int dmz_reset_zones(struct dmz_dev *dev);
extern int dmz_write_block(struct dmz_dev *dev, __u64 block, __u8 *buf);
extern int dmz_read_block(struct dmz_dev *dev, __u64 block, __u8 *buf);

extern __u32 dmz_crc32(__u32 crc, const void *address, size_t length);

extern int dmz_locate_metadata(struct dmz_dev *dev);
extern int dmz_write_super(struct dmz_dev *dev, __u64 gen, __u64 offset);
extern int dmz_format(struct dmz_dev *dev);
extern int dmz_check(struct dmz_dev *dev);
extern int dmz_repair(struct dmz_dev *dev);
extern int dmz_init_dm(int log_level);
extern int dmz_start(struct dmz_dev *dev);
extern int dmz_stop(struct dmz_dev *dev, char *dm_dev);

#endif /* __DMZ_H__ */
