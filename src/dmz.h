/*
 * This file is part of dm-zoned tools.
 *
 * Copyright (C) 2016, Western Digital. All rights reserved.
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

#ifndef __DMZ_H__
#define __DMZ_H__

/***** Including files *****/

#define _LARGEFILE64_SOURCE

#include "config.h"

#include <limits.h>
#include <sys/types.h>
#include <linux/blkzoned.h>

/***** Type definitions *****/

/*
 * Metadata version.
 */
#define DMZ_META_VER	1

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
	__le32		magic;				/*    4 */

	/* Metadata version number */
	__le32		version;			/*    8 */

	/* This block number */
	__le64		sb_block;			/*   16 */

	/* The number of metadata blocks, including the super block */
	__le64		nr_meta_blocks;			/*   20 */

	/* The number of entries in the mapping table */
	__le32		nr_chunks;			/*   24 */

	/* The number of blocks used for the chunk mapping table */
	__le32		nr_map_blocks;			/*   28 */

	/* The number of blocks used for the block bitmaps */
	__le32		nr_bitmap_blocks;		/*   32 */

	__u8		reserved[4064];			/* 4096 */

};

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
};

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

/*
 * Chunk mapping table metadata: 512 8-bytes entries per 4KB block.
 */
#define DMZ_MAP_ENTRIES		(DMZ_BLOCK_SIZE / sizeof(struct dm_zoned_map))
#define DMZ_MAP_ENTRIES_MASK	(DMZ_MAP_ENTRIES - 1)
#define DMZ_MAP_UNMAPPED	UINT_MAX

/*
 * Number of sequential zones reserved for reclaim.
 */
#define DMZ_NR_RESERVED		16

/*
 * Device flags.
 */
#define DMZ_VERBOSE		0x00000001
#define DMZ_VVERBOSE		0x00000002
#define DMZ_ZONED_HA		0x00000010
#define DMZ_ZONED_HM		0x00000020

/*
 * Operations.
 */
enum {
	DMZ_FORMAT = 1,
	DMZ_CHECK,
	DMZ_REPAIR,
};

/*
 * Device descriptor.
 */
typedef struct dmz_dev {

	/* Device file path and basename */
	char		*path;
	char		*name;
	unsigned int	flags;
	int		op;

	/* Device info */
	__u64		capacity;

	unsigned int	nr_zones;
	unsigned int	nr_meta_zones;
	unsigned int	nr_meta_blocks;
	unsigned int	nr_chunks;

	struct blk_zone	*zones;

	size_t		zone_nr_sectors;
	size_t		zone_nr_blocks;

	/* First metadata zone */
	struct blk_zone	*sb_zone;
	__u64		sb_block;

	/* Zone bitmaps */
	size_t		zone_nr_bitmap_blocks;
	unsigned int	nr_bitmap_blocks;
	__u64		bitmap_block;

	/* Mapping table */
	unsigned int	nr_map_blocks;
	__u64		map_block;

	/* Device file descriptor */
	int		fd;

} dmz_dev_t;

#define dmz_dev_is_ha(dev)	((dev)->flags & DMZ_ZONED_HA)
#define dmz_dev_is_hm(dev)	((dev)->flags & DMZ_ZONED_HM)
#define dmz_dev_is_zoned(dev)	(dmz_dev_is_ha(dev) || dmz_dev_is_hm(dev))

#define dmz_zone_type(z)        (z)->type
#define dmz_zone_conv(z)	((z)->type == BLK_ZONE_TYPE_CONVENTIONAL)
#define dmz_zone_seq_req(z)	((z)->type == BLK_ZONE_TYPE_SEQWRITE_REQ)
#define dmz_zone_seq_pref(z)	((z)->type == BLK_ZONE_TYPE_SEQWRITE_PREF)
#define dmz_zone_rnd(z)		(dmz_zone_conv(z) || dmz_zone_seq_pref(z))

static inline const char *
dmz_zone_type_str(struct blk_zone *zone)
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

static inline const char *
dmz_zone_cond_str(struct blk_zone *zone)
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
#define dmz_zone_id(dev, zone)	((unsigned int)(dmz_zone_sector(zone) \
						/ (dev)->zone_nr_sectors))
#define dmz_zone_length(z)	(z)->len
#define dmz_zone_wp_sector(z)	(z)->wp
#define dmz_zone_need_reset(z)	(int)(z)->reset
#define dmz_zone_non_seq(z)	(int)(z)->non_seq

int dmz_open_dev(struct dmz_dev *dev);
void dmz_close_dev(struct dmz_dev *dev);
int dmz_reset_zone(struct dmz_dev *dev, struct blk_zone *zone);
int dmz_reset_zones(struct dmz_dev *dev);
int dmz_write_block(struct dmz_dev *dev, __u64 block, char *buf);

int dmz_format(struct dmz_dev *dev);
int dmz_check(struct dmz_dev *dev);
int dmz_repair(struct dmz_dev *dev);

#endif /* __DMZ_H__ */
