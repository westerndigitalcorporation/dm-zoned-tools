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
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <assert.h>
#include <asm/byteorder.h>

#define FORCE_SB0_BAD			(0)
#define FORCE_SB1_BAD			(0)
#define FORCE_SB1_SEARCH_BAD		(0)

#define DIV_ROUND_UP(n,d)		(((n) + (d) - 1) / (d))
#define DMZ_MAP_UNMAPPED_LE32		__cpu_to_le32(DMZ_MAP_UNMAPPED)

/* Calculate location of metadata blocks */
static void calc_dmz_meta_data_loc(struct dmz_dev *dev,
				   unsigned int *max_nr_meta_zones,
				   __u32 *nr_active_zones,
				   unsigned int *last_md_zone_id)
{
	struct blk_zone *zone;
	*last_md_zone_id = 0;
	*nr_active_zones = 0;

	/* Count useable zones */
	for (unsigned int i = 0; i < dev->nr_zones; i++) {
		zone = &dev->zones[i];

		if (dmz_zone_cond(zone) == BLK_ZONE_COND_OFFLINE) {
			printf("%s: Ignoring inactive zone %u\n",
			       dev->name,
			       dmz_zone_id(dev, zone));
			continue;
		}

		(*nr_active_zones)++;

		if (dmz_zone_rnd(zone)) {
			if (dev->sb_zone == NULL) {
				dev->sb_zone = zone;
				*last_md_zone_id = i;
				*max_nr_meta_zones = 1;
			} else if (*last_md_zone_id == (i - 1)) {
				*last_md_zone_id = i;
				(*max_nr_meta_zones)++;
			}
		}

	}

	assert(dev->sb_zone);
	dev->sb_block = dmz_sect2blk(dmz_zone_sector(dev->sb_zone));

}

/* Check the contents of a super block */
static int check_superblock(struct dmz_dev *dev, __u32 nr_zones,
			    __u8 *block_buffer, __u64 address,
			    int print_error)
{
	struct dm_zoned_super *sb;
	__u32 stored_crc, calculated_crc;

	sb = (struct dm_zoned_super *) block_buffer;

	/* First, check magic */
	if (__le32_to_cpu(sb->magic) != DMZ_MAGIC) {
		if (print_error)
			fprintf(stderr, 
			"Super block at 0x%llx failed magic check "
			"expect 0x%x read 0x%x\n",
			address, DMZ_MAGIC, __le32_to_cpu(sb->magic));
		return -1;
	}

	/* Now lets check the CRC */
	stored_crc = __le32_to_cpu(sb->crc);
	sb->crc = 0;

	calculated_crc = dmz_crc32(sb->gen, block_buffer, DMZ_BLOCK_SIZE);

	if (calculated_crc != stored_crc) {
		if (print_error)
			fprintf(stderr, 
			"Super block at 0x%llx failed crc check, "
			"expect 0x%x read 0x%x\n",
			address, calculated_crc, stored_crc);
		return -1;
	}

	/* Finally, the version */
	if (__le32_to_cpu(sb->version) != DMZ_META_VER) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed version check, "
			"expect 0x%x read 0x%x\n",
			address, DMZ_META_VER, __le32_to_cpu(sb->version));
		return -1;
	}

	if (__le64_to_cpu(sb->sb_block) != address) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed location check, "
			"expect 0x%llx read 0x%llx\n",
			address, address, __le64_to_cpu(sb->sb_block));
		return -1;
	}

	/* Check total number of metadata blocks are expected */
	__u64 expected_nr_meta_blocks =
		1 + __le32_to_cpu(sb->nr_map_blocks) +
		__le32_to_cpu(sb->nr_bitmap_blocks);

	if (__le64_to_cpu(sb->nr_meta_blocks) != expected_nr_meta_blocks) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed number of metadata blocks "
			"check, expect 0x%llx read 0x%llx\n",
			address, expected_nr_meta_blocks,
			__le64_to_cpu(sb->nr_meta_blocks));
		return -1;
	}

	__u32 nr_meta_zones =
		DIV_ROUND_UP(expected_nr_meta_blocks, dev->zone_nr_blocks);

	/* Check to make number of chunks is as expected */
	__u32 expected_nr_chunks =
		nr_zones - ((nr_meta_zones * 2) +
		__le32_to_cpu(sb->nr_reserved_seq));

	if (__le32_to_cpu(sb->nr_chunks) != expected_nr_chunks) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed number of chunks check, "
			"expect 0x%x read 0x%x\n",
			address, expected_nr_chunks,
			__le32_to_cpu(sb->nr_chunks));
		return -1;
	}
	
	/* Check to make sure nr_chunks matches nr_map_blocks */
	__u32 expected_nr_map_blocks =
		DIV_ROUND_UP(__le32_to_cpu(sb->nr_chunks), DMZ_MAP_ENTRIES);

	if (__le32_to_cpu(sb->nr_map_blocks) != expected_nr_map_blocks) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed number of map blocks, "
			"expect 0x%x read 0x%x\n",
			address, expected_nr_map_blocks,
			__le32_to_cpu(sb->nr_map_blocks));
		return -1;
	}

	/* Check to make sure # of zones match # of zone bitmap blocks */
	size_t zone_nr_bitmap_blocks =
		dev->zone_nr_blocks >> (DMZ_BLOCK_SHIFT + 3);
	__u32 expected_nr_bitmap_blocks = dev->nr_zones * zone_nr_bitmap_blocks;
	
	if (__le32_to_cpu(sb->nr_bitmap_blocks) != expected_nr_bitmap_blocks) {
		if (print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed number of bitmap blocks "
			"check, expect 0x%x read 0x%x\n",
			address, expected_nr_bitmap_blocks,
			__le32_to_cpu(sb->nr_bitmap_blocks));
		return -1;
	}

	printf("Super block at 0x%llx with gen number %llu passed check\n",
		address, __le64_to_cpu(sb->gen));

	return 0;

}

/* Check if the contents of 2 super block matches */
static int matching_superblock(struct dm_zoned_super *sb_0,
			       struct dm_zoned_super *sb_1)
{
	if ((sb_0->nr_meta_blocks == sb_1->nr_meta_blocks) &&
	(sb_0->nr_reserved_seq == sb_1->nr_reserved_seq) &&
	(sb_0->nr_chunks == sb_1->nr_chunks) &&
	(sb_0->nr_map_blocks == sb_1->nr_map_blocks) &&
	(sb_0->nr_bitmap_blocks == sb_1->nr_bitmap_blocks))
		return 1;

	return 0;

}

/* Read in zone bitmaps for a given zone */
static int read_zone_bitmap(struct dmz_dev *dev, unsigned int zone_id,
			    __u64 bitmap_block, size_t zone_nr_bitmap_blocks,
			    __u8 *buf, __u64 *bitmap_block_address)
{
	__u64 starting_block = bitmap_block + (zone_id * zone_nr_bitmap_blocks);
	*bitmap_block_address = starting_block;
	int status;

	for (unsigned int i = 0; i < zone_nr_bitmap_blocks; i++) {
		__u64 block = starting_block + i;
		char *c_ptr = (char *)(buf + (i * DMZ_BLOCK_SIZE));

		status = dmz_read_block(dev, block, c_ptr);

		if (status) {
			fprintf(stderr,
				"Error reading bitmap block at 0x%llx\n",
				block);
			return -1;
		}

	}

	return 0;

}

/* Write out zone bitmaps for a given zone */
static int write_zone_bitmap(struct dmz_dev *dev, unsigned int zone_id,
			    __u64 bitmap_block, size_t zone_nr_bitmap_blocks,
			    __u8 *buf, __u64 *bitmap_block_address)
{
	__u64 starting_block = bitmap_block + (zone_id * zone_nr_bitmap_blocks);
	*bitmap_block_address = starting_block;
	int status;

	for (unsigned int i = 0; i < zone_nr_bitmap_blocks; i++) {
		__u64 block = starting_block + i;
		char *c_ptr = (char *)(buf + (i * DMZ_BLOCK_SIZE));

		status = dmz_write_block(dev, block, c_ptr);

		if (status) {
			fprintf(stderr,
				"Error writing bitmap block at 0x%llx\n",
				block);
			return -1;
		}

	}

	return 0;

}

static int check_zone_mapping_block(struct dmz_dev *dev,
				    __u64 block_addr,
				    __u8 *map_zone_entry_bm,
				    unsigned int bm_size, int repair)
{
	__u8 map_block_buffer[DMZ_BLOCK_SIZE];
	int found_error = 0;
	int status;

	status = dmz_read_block(dev, block_addr, (char *)map_block_buffer);

	if (status) {
		fprintf(stderr,
			"Error reading map block at 0x%llx\n",
			block_addr);
		return 1;
	}

	/* Lets do mapping check in multiple rounds,
	this will make the logic cleaner but less efficient */
	struct dm_zoned_map *dmap;
	int valid_zone_ids = 1;

	/* First, lets make sure the zone ids are valid and
	that there are no redundant mappings */
	dmap = (struct dm_zoned_map *)map_block_buffer;

	for (unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
		__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
		__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);
		int invalid_dzone_id = 0;
		int invalid_bzone_id = 0;

		if ((dzone_id != DMZ_MAP_UNMAPPED) &&
			(dzone_id >= dev->nr_zones)) {

			fprintf(stderr,
				"Invalid dzone id 0x%x for mapping entry 0x%x\n",
				dzone_id, j);

			if (repair)
				dmap->dzone_id = DMZ_MAP_UNMAPPED_LE32;
			else
				invalid_dzone_id = 1;

		}

		if ((bzone_id != DMZ_MAP_UNMAPPED) &&
			(bzone_id >= dev->nr_zones)) {

			fprintf(stderr,
				"Invalid bzone id 0x%x for mapping entry 0x%x\n",
				bzone_id, j);

			if (repair)
				dmap->bzone_id = DMZ_MAP_UNMAPPED_LE32;
			else
				invalid_bzone_id = 1;

		}

		if (invalid_dzone_id || invalid_bzone_id) {
			valid_zone_ids = 0;
			continue;
		}

		/* Check for redundant zone mapping */
		if (dzone_id != DMZ_MAP_UNMAPPED) {
			int element_idx = dzone_id / 8;
			int bit_idx = (dzone_id % 8);

			/* Check if zone bit is set */
			if (map_zone_entry_bm[element_idx] & (1 << bit_idx)) {

				fprintf(stderr,
					"Error found repeat "
					"zone id 0x%x as dzone "
					"for mapping entry 0x%x\n",
					dzone_id, j);

				if (repair)
					dmap->dzone_id =
						DMZ_MAP_UNMAPPED_LE32;
				else 
					valid_zone_ids = 0;

			} else {
				/* Set the bit */
				map_zone_entry_bm[element_idx] |= (1 << bit_idx);
			}

		}

		/* Check for redundant zone mapping */
		if (bzone_id != DMZ_MAP_UNMAPPED) {
			int element_idx = bzone_id / 8;
			int bit_idx = (bzone_id % 8);

			/* Check if zone bit is set */
			if (map_zone_entry_bm[element_idx] & (1 << bit_idx)) {

				fprintf(stderr, 
					"Error found repeat zone "
					"id 0x%x as bzone for "
					"mapping entry 0x%x\n",
					bzone_id, j);

				if (repair)
					dmap->bzone_id = DMZ_MAP_UNMAPPED_LE32;
				else
					valid_zone_ids = 0;

			} else {
				/* Set the bit */
				map_zone_entry_bm[element_idx] |= (1 << bit_idx);
			}

		}

	}

	if (!valid_zone_ids) {
		fprintf(stderr, "Found invalid zone ids in mapping\n");
		found_error = 1;
	}

	/* Now, lets make sure the zone ids are used as intended */
	dmap = (struct dm_zoned_map *)map_block_buffer;

	for (unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
		__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
		__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);

		if ((dzone_id != DMZ_MAP_UNMAPPED) &&
			(dzone_id >= dev->nr_zones)) {
			continue;
		}

		if ((bzone_id != DMZ_MAP_UNMAPPED) &&
			(bzone_id >= dev->nr_zones)) {
			continue;
		}

		/* Bzone should not be squential only zone */
		if (bzone_id != DMZ_MAP_UNMAPPED) {
			struct blk_zone *bzone = &dev->zones[bzone_id];

			if (!dmz_zone_rnd(bzone)) {

				fprintf(stderr,
					"Invalid bzone mapping "
					"(0x%x) to a non-random "
					"writable zone for mapping "
					"entry 0x%x\n", 
					bzone_id, j);

				if (repair)
					dmap->bzone_id = DMZ_MAP_UNMAPPED_LE32;
				else
					found_error = 1;

			}
		}

		if (dzone_id == DMZ_MAP_UNMAPPED) {
			/* If dzone is not mapped then we expect
			bzone to be not mapped as well */
			if (bzone_id != DMZ_MAP_UNMAPPED) {
					
				fprintf(stderr,
					"Unexpected bzone mapping "
					"(0x%x) as dzone is "
					"unmapped for mapping "
					"entry 0x%x\n", 
					bzone_id, j);

				if (repair)
					dmap->bzone_id = DMZ_MAP_UNMAPPED_LE32;
				else
					found_error = 1;

			}
		} else {
			struct blk_zone *dzone =
				&dev->zones[dzone_id];

			if (dmz_zone_rnd(dzone)) {
				/* If dzone is random, then
				no need for bzone*/
				if (bzone_id != DMZ_MAP_UNMAPPED) {

					fprintf(stderr,
						"Unexpected bzone "
						"mapping (0x%x) as "
						"dzone is random "
						"writable for "
						"mapping entry "
						"0x%x\n",
						bzone_id, j);

					if (repair)
						dmap->bzone_id =
							DMZ_MAP_UNMAPPED_LE32;
					else
						found_error = 1;

				}
			}

			if (dmz_zone_seq_req(dzone)) {
				/* Zone should not be empty */
				if (dmz_zone_empty(dzone)) {
					fprintf(stderr,
						"Warning, dzone "
						"(0x%x) is empty "
						"for mapping "
						"entry 0x%x\n",
						dzone_id, j);
				}
			}

		}

	}

	/* Commit the repaired changes */
	if (repair) {

		status = dmz_write_block(dev, block_addr, (char *)map_block_buffer);
		
		if (status) {
			fprintf(stderr,
				"Error writing map block at 0x%llx\n", block_addr);
			found_error = 1;
		}

	}

	return found_error;

}

static int check_zone_mappings(struct dmz_dev *dev, __u64 map_block,
			      __u32 nr_map_blocks, int repair)
{
	__u8 map_zone_entry_bm[DIV_ROUND_UP(dev->nr_zones, 8)];
	int found_error = 0;
	int status;

	for (unsigned int i = 0; i < DIV_ROUND_UP(dev->nr_zones, 8); i++) {
		map_zone_entry_bm[i] = 0;
	}

	printf("Starting mapping table verification at 0x%llx for %u blocks\n",
		map_block, nr_map_blocks);

	for (unsigned int i = 0; i < nr_map_blocks; i++) {

		status = check_zone_mapping_block(dev, map_block + i,
			map_zone_entry_bm, DIV_ROUND_UP(dev->nr_zones, 8),
			repair);

		if(status)
			found_error = 1;

	}

	printf("Mapping table verification complete\n");

	return found_error;

}

static int check_mapped_zone_bitmap_overlap(struct dmz_dev *dev,
					    __u64 block_addr,
					    __u64 bitmap_block,
					    size_t zone_nr_bitmap_blocks,
					    int repair)
{
	__u8 map_block_buffer[DMZ_BLOCK_SIZE];
	int found_error = 0;
	int status;

	status = dmz_read_block(dev, block_addr, (char *)map_block_buffer);

	if (status) {
		fprintf(stderr, "Error reading map block at 0x%llx\n",
			block_addr);
		return 1;
	}

	struct dm_zoned_map *dmap;
	dmap = (struct dm_zoned_map *)map_block_buffer;

	for (unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
		__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
		__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);

		if ((dzone_id == DMZ_MAP_UNMAPPED) ||
			(bzone_id == DMZ_MAP_UNMAPPED))
			continue;

		assert ((dzone_id != DMZ_MAP_UNMAPPED) &&
			(bzone_id != DMZ_MAP_UNMAPPED));

		__u8 dzone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];
		__u8 bzone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];
		__u64 dzone_bitmap_block_address;
		__u64 bzone_bitmap_block_address;

		/* Read in the zone bits */
		if (read_zone_bitmap(dev, dzone_id, bitmap_block,
			zone_nr_bitmap_blocks,
			dzone_bitmap_buffer,
			&dzone_bitmap_block_address))
			continue;

		if (read_zone_bitmap(dev, bzone_id, bitmap_block,
			zone_nr_bitmap_blocks,
			bzone_bitmap_buffer,
			&bzone_bitmap_block_address))
			continue;

		/* Make sure there are no overlaps */
		for (unsigned int k = 0; k < zone_nr_bitmap_blocks *
			DMZ_BLOCK_SIZE; k++) {

			__u8 overlap_bitmask =
				dzone_bitmap_buffer[k] & bzone_bitmap_buffer[k];

			if (!overlap_bitmask)
				continue;

			fprintf(stderr,
				"Error in zone bit maps, "
				"overlap between dzone and "
				"bzone.\n");

			fprintf(stderr,
				"dzone %u at block offset "
				"%u in bit block 0x%llx "
				"with value 0x%x\n",
				dzone_id, k, 
				dzone_bitmap_block_address,
				dzone_bitmap_buffer[k]);

			fprintf(stderr,
				"bzone %u at block "
				"offset %u in bit "
				"block 0x%llx with "
				"value 0x%x\n",
				bzone_id, k,
				bzone_bitmap_block_address,
				bzone_bitmap_buffer[k]);

			if (repair) {
				/* Assume bzone has precedence,
				zero the overlapped bits in dzone */
				dzone_bitmap_buffer[k] &= ~overlap_bitmask;
			} else {
				found_error = 1;
			}

		}

		/* Commit the repaired changes */
		if (repair) {

			status = write_zone_bitmap(dev, dzone_id, bitmap_block,
				zone_nr_bitmap_blocks,
				dzone_bitmap_buffer,
				&dzone_bitmap_block_address);

			if (status)
				found_error = 1;

			status = write_zone_bitmap(dev, bzone_id, bitmap_block,
				zone_nr_bitmap_blocks,
				bzone_bitmap_buffer,
				&bzone_bitmap_block_address);

			if (status)
				found_error = 1;
		}

	}

	return found_error;

}


static int check_zone_bitmap_block(struct dmz_dev *dev, unsigned int zone_id,
				   struct blk_zone *zone,
				   __u64 bitmap_block, size_t zone_nr_bitmap_blocks,
				   int repair)
{
	__u8 zone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];
	__u64 bitmap_block_address;
	int found_error = 0;
	int status;

	assert(dmz_zone_seq_req(zone));

	/* Read in the zone bits */
	status = read_zone_bitmap(dev, zone_id, bitmap_block, zone_nr_bitmap_blocks,
		zone_bitmap_buffer, &bitmap_block_address);

	if (status)
		return 1;

	assert(zone->wp >= dmz_zone_sector(zone));
	__u64 wp_sect_offset = zone->wp - dmz_zone_sector(zone);
	assert((wp_sect_offset % (1 << DMZ_BLOCK_SECTORS_SHIFT)) == 0);
	__u64 wp_block = dmz_sect2blk(wp_sect_offset);

	/* No bits should be set >= WP */
	for (unsigned int j = wp_block; j < dev->zone_nr_blocks; j++) {
		int element_idx = j / 8;
		int bit_idx = (j % 8);

		assert (element_idx < (int)(zone_nr_bitmap_blocks
			* DMZ_BLOCK_SIZE));

		if (zone_bitmap_buffer[element_idx] & (1 << bit_idx)) {

			fprintf(stderr,
				"Error in zone bit map, valid bits after "
				"zone wp. Zone %u at block offset %u in "
				"bit block 0x%llx\n",
				zone_id, j, bitmap_block_address);

			if (repair) {
				/* Turn off the bit */
				zone_bitmap_buffer[element_idx] &=
					~(1 << bit_idx);
			} else {
				found_error = 1;
			}

		}

	}

	if (repair) {
		status = write_zone_bitmap(dev, zone_id, bitmap_block, zone_nr_bitmap_blocks,
			zone_bitmap_buffer, &bitmap_block_address);
		if (status)
			found_error = 1;
	}

	return found_error;

}

static int check_zone_bitmaps(struct dmz_dev *dev, __u64 bitmap_block,
	__u32 nr_bitmap_blocks, size_t zone_nr_bitmap_blocks,
	__u64 map_block, __u32 nr_map_blocks, int repair)
{
	int found_error = 0;
	int status;

	printf("Starting zone bitmaps verification at 0x%llx for %u blocks\n",
		bitmap_block, nr_bitmap_blocks);

	/* Again, let's do the check in multiple loops...
	First, make sure the bitmaps for seq zones are correct
	(set bits must be less than WP) */
	for (unsigned int i = 0; i < dev->nr_zones; i++) {
		struct blk_zone *zone = &dev->zones[i];

		if (!dmz_zone_seq_req(zone))
			continue;

		status = check_zone_bitmap_block(dev, i, zone, bitmap_block,
			zone_nr_bitmap_blocks, repair);

		if (status)
			found_error = 1;

	}

	/* Now we make sure there are no overlaps between a dzone's bitmap and 
	its associated bzone's bitmap */
	for (unsigned int i = 0; i < nr_map_blocks; i++) {
		
		status = check_mapped_zone_bitmap_overlap(dev, map_block + i,
			bitmap_block, zone_nr_bitmap_blocks, repair);

		if (status)
			found_error = 1;

	}

	printf("Zone bitmaps verification complete\n");

	return found_error;

}

/* Check zone mappings and bitmaps for a metadata set */
static int check_zone_mapping_and_bitmap(struct dmz_dev *dev, __u64 sb_address,
					 struct dm_zoned_super *sb, int repair)
{
	__u64 map_block;
	__u32 nr_map_blocks;
	__u64 bitmap_block;
	__u32 nr_bitmap_blocks;
	int status;
	size_t zone_nr_bitmap_blocks;
	int found_error = 0;

	map_block = sb_address + 1;
	nr_map_blocks = __le32_to_cpu(sb->nr_map_blocks);

	/* First, lets do zone mapping check */
	status = check_zone_mappings(dev, map_block, nr_map_blocks, repair);
	if(status)
		found_error = 1;

	bitmap_block = map_block + nr_map_blocks;
	nr_bitmap_blocks = __le32_to_cpu(sb->nr_bitmap_blocks);
	zone_nr_bitmap_blocks = dev->zone_nr_blocks >> (DMZ_BLOCK_SHIFT + 3);

	/* Then let's do zone bitmap check*/
	status = check_zone_bitmaps(dev, bitmap_block,nr_bitmap_blocks,
		zone_nr_bitmap_blocks, map_block, nr_map_blocks, repair);
	if(status)
		found_error = 1;

	if (found_error)
		printf("Found errors in metadata blocks in "
			"range 0x%llx to 0x%llx\n",
			map_block, bitmap_block + nr_bitmap_blocks - 1);
	else
		printf("No errors found in metadata blocks in range "
			"0x%llx to 0x%llx\n",
			map_block, bitmap_block + nr_bitmap_blocks - 1);

	return found_error;

}

/*
 * Check a device metadata, repair if asked to
 */
int dmz_check(struct dmz_dev *dev, int repair)
{
	__u8 sb_block_buffer[2][DMZ_BLOCK_SIZE];
	__u64 sb_address[2] = {0};
	int valid_sb[2] = {0};
	int valid_md_blocks[2] = {0};
	int status;
	unsigned int max_nr_meta_zones = 0;
	unsigned int i;
	__u32 nr_active_zones = 0;
	unsigned int last_md_zone_id;
	
	printf("Start checking process...\n");

	calc_dmz_meta_data_loc(dev, &max_nr_meta_zones, &nr_active_zones,
		&last_md_zone_id);

	sb_address[0] = dev->sb_block;
	status = dmz_read_block(dev, sb_address[0], (char *)sb_block_buffer[0]);

	#if FORCE_SB0_BAD
	status = -1;
	#endif

	if (status) {
		fprintf(stderr,
			"Error reading super block at 0x%llx\n",
			sb_address[0]);
	} else {
		status = check_superblock(dev, nr_active_zones,
				sb_block_buffer[0], sb_address[0], 1);
		if (!status)
			valid_sb[0] = 1;
	}

	if (valid_sb[0]) {
		/* We've got a good sb[0], now lets calculate
		location of sb[1] */
		struct dm_zoned_super *sb =
			(struct dm_zoned_super *) sb_block_buffer[0];
		dev->nr_meta_zones =
			DIV_ROUND_UP(__le64_to_cpu(sb->nr_meta_blocks),
			dev->zone_nr_blocks);
		sb_address[1] =
			sb_address[0] + (dev->nr_meta_zones * dev->zone_nr_blocks);

		/* We should add additional check to make sure sb_address[1] is
		   not outside of nr_active_zones bounds*/
		status = dmz_read_block(dev, sb_address[1],
			(char *)sb_block_buffer[1]);

		#if FORCE_SB1_BAD
		status = -1;
		#endif

		if (status) {
			fprintf(stderr,
				"Error reading super block at 0x%llx\n",
				sb_address[1]);
		} else {
			status = check_superblock(dev, nr_active_zones,
				sb_block_buffer[1], sb_address[1], 1);

			if (!status)
				valid_sb[1] = 1;

		}

	} else {
		/* We've don't have a good sb[0],
		now lets find location of sb[1] */
		sb_address[1] = sb_address[0] + dev->zone_nr_blocks;

		printf("Searching for second super block\n");

		for (i = 0; i < max_nr_meta_zones - 1; i++) {
			printf("\tAt 0x%llx\n", sb_address[1]);

			status = dmz_read_block(dev, sb_address[1],
				(char *)sb_block_buffer[1]);

			#if FORCE_SB1_SEARCH_BAD
			status = -1;
			#endif

			if (!status) {
				status = check_superblock(dev, nr_active_zones,
					sb_block_buffer[1], sb_address[1], 0);

				if (!status) {
					valid_sb[1] = 1;
					break;
				}
			}

			sb_address[1] += dev->zone_nr_blocks;

		}

		if (valid_sb[1])
			printf("Found second super block\n");
		else
			printf("Cannot find second super block\n");

	}

	/* We've got no valid super block... */
	if (!valid_sb[0] && !valid_sb[1]) {
		fprintf(stderr, "No valid superblock found\n");
		/* To do: call format? */
	}

	/* Both super blocks are valid */
	if (valid_sb[0] && valid_sb[1]) {
		struct dm_zoned_super *sb_0 =
			(struct dm_zoned_super *) sb_block_buffer[0];
		struct dm_zoned_super *sb_1 =
			(struct dm_zoned_super *) sb_block_buffer[1];

		if (__le64_to_cpu(sb_0->gen) != __le64_to_cpu(sb_1->gen)) {
			fprintf(stderr,
				"Warning, generation number of the two super "
				"blocks do not match.\n");
		}

		if (!matching_superblock(sb_0, sb_1)) {
			fprintf(stderr,
				"Warning, the contents of two super "
				"blocks do not match.\n");
		}

	} 

	if (valid_sb[0]) {
		status = check_zone_mapping_and_bitmap(dev, sb_address[0],
			(struct dm_zoned_super *) sb_block_buffer[0], 0);

		if (!status)
			valid_md_blocks[0] = 1;
		else
			valid_md_blocks[0] = 0;

	} else {
		valid_md_blocks[0] = 0;
	}

	if (valid_sb[1]) {
		status = check_zone_mapping_and_bitmap(dev, sb_address[1],
			(struct dm_zoned_super *) sb_block_buffer[1], 0);

		if (!status)
			valid_md_blocks[1] = 1;
		else
			valid_md_blocks[1] = 0;

	} else {
		valid_md_blocks[1] = 0;
	}

	printf("Checking done\n");

	if (!repair)
		return 0;

	/* Repair operation starts below*/
	printf("Start repairing process\n");

	int repair_error = 0;
	unsigned int ref_sb_index;
	unsigned int cpy_sb_index;

	/* We've got no valid metadata blocks... */
	if (!valid_md_blocks[0] && !valid_md_blocks[1]) {
		unsigned int recv_sb_index;

		fprintf(stderr, "Two sets of invalid metadata blocks\n");

		/* Lets try to repair one set of the md blocks and
		then do copy. Use the newest sb to repair */
		if (valid_sb[0] && valid_sb[1]) {
			struct dm_zoned_super *sb_0 =
				(struct dm_zoned_super *) sb_block_buffer[0];
			struct dm_zoned_super *sb_1 =
				(struct dm_zoned_super *) sb_block_buffer[1];

			if (__le64_to_cpu(sb_0->gen) >= __le64_to_cpu(sb_1->gen))
				recv_sb_index = 0;
			else
				recv_sb_index = 1;
		}

		/* Select which ever is valid */
		if (valid_sb[0] && !valid_sb[1])
			recv_sb_index = 0;

		if (!valid_sb[0] && valid_sb[1])
			recv_sb_index = 1;

		/* Don't have anything to base repair off of... */
		if (!valid_sb[0] && !valid_sb[1]) {
			printf("No valid metadata to reference for repair, "
				"please re-format the disk\n");
			repair_error = 1;
			goto repair_end;
		}

		printf("Starting to recover metadata set %u\n", recv_sb_index);

		/* Let's try to recover the zone mapping and bitmaps */
		check_zone_mapping_and_bitmap(dev, sb_address[recv_sb_index],
			(struct dm_zoned_super *) sb_block_buffer[recv_sb_index],
			1);

		/* And set the reference sb to what we've recovered */
		ref_sb_index = recv_sb_index;

	} else {
		/* If both sets of md are good, then we are done */
		if (valid_md_blocks[0] && valid_md_blocks[1]) {
			printf("No need for repair\n");
			goto repair_end;
		} else {
			/* If one of the md set is bad, then copy
			the good one over. Only a single set of valid md blocks */
			assert((valid_md_blocks[0] && !valid_md_blocks[1]) ||
				(!valid_md_blocks[0] && valid_md_blocks[1]));

			if (valid_md_blocks[0])
				ref_sb_index = 0;
			else 
				ref_sb_index = 1;

		}
	}

	/* Only overwrite the other set of metadata if needed! */
	assert (1 >= ref_sb_index);
	cpy_sb_index = 1 - ref_sb_index;

	printf("Using superblock %d at address 0x%llxx as reference\n",
		ref_sb_index, sb_address[ref_sb_index]);

	__u64 src_blk;
	__u64 dst_blk;
	__u8 block_buffer[DMZ_BLOCK_SIZE];
	struct dm_zoned_super *sb_ref = NULL;
	struct dm_zoned_super *sb_cpy = NULL;

	if (ref_sb_index == 0) {
		/* We want to copy from sb[0] to sb[1]
		We need to calculate where to copy to... */
		sb_ref = (struct dm_zoned_super *) sb_block_buffer[0];
		dev->nr_meta_zones =
			DIV_ROUND_UP(__le64_to_cpu(sb_ref->nr_meta_blocks),
			dev->zone_nr_blocks);
		sb_address[1] =
			sb_address[0] +
			(dev->nr_meta_zones * dev->zone_nr_blocks);
	}

	src_blk = sb_address[ref_sb_index];
	sb_ref = (struct dm_zoned_super *) sb_block_buffer[ref_sb_index];
	dst_blk = sb_address[cpy_sb_index];
	sb_cpy = (struct dm_zoned_super *) sb_block_buffer[cpy_sb_index];

	/* Make sure there are enough room for the copy... */
	if (sb_address[0] + __le64_to_cpu(sb_ref->nr_meta_blocks) >
		sb_address[1]) {
		repair_error = 1;
		fprintf(stderr,
			"Not enough spacing between metadata sets, expect "
			"at least %llu blocks\n",
			__le64_to_cpu(sb_ref->nr_meta_blocks));
		goto repair_end;
	}

	unsigned int total_nr_meta_zones =
		DIV_ROUND_UP(__le64_to_cpu(sb_ref->nr_meta_blocks),
		dev->zone_nr_blocks) * 2;

	if (total_nr_meta_zones > max_nr_meta_zones) {
		repair_error = 1;
		fprintf(stderr,
			"Error not enough random writeable zones to "
			"fit metadata (%llu) blocks required\n",
			__le64_to_cpu(sb_ref->nr_meta_blocks));
		goto repair_end;
	}

	struct blk_zone *last_md_zone = &dev->zones[last_md_zone_id];
	__u64 last_md_block = dmz_sect2blk(dmz_zone_sector(last_md_zone)) +
		dev->zone_nr_blocks - 1;

	if (sb_address[1] + __le64_to_cpu(sb_ref->nr_meta_blocks) > last_md_block) {
		repair_error = 1;
		fprintf(stderr,
			"Error not not enough random writeable zones to "
			"fit last metadata block, have 0x%llx need 0x%llx blocks\n"
			, sb_address[1] + __le64_to_cpu(sb_ref->nr_meta_blocks),
			last_md_block);
		goto repair_end;
	}

	printf("Start metadata copying\n");
	printf("Src: 0x%llx\n", src_blk);
	printf("Dst: 0x%llx\n", dst_blk);
	printf("Len: %llu\n", __le64_to_cpu(sb_ref->nr_meta_blocks));

	/* Generate a new SB from reference */
	*sb_cpy = *sb_ref;
	sb_cpy->sb_block = __cpu_to_le64(dst_blk);
	sb_cpy->crc = 0;
	sb_cpy->crc = __cpu_to_le32(dmz_crc32(__le64_to_cpu(sb_ref->gen),
		sb_cpy, DMZ_BLOCK_SIZE));

	status = dmz_write_block(dev, dst_blk,
		(char *)sb_block_buffer[cpy_sb_index]);

	if (status) {
		fprintf(stderr, "Error writing block 0x%llx\n", dst_blk);
		repair_error = 1;
		goto repair_end;
	}

	/* And copy the rest of the metadata blocks... */
	for (unsigned int i = 1; i < __le64_to_cpu(sb_ref->nr_meta_blocks); i++) {
		status = dmz_read_block(dev, src_blk + i, (char *)block_buffer);

		if (status) {
			fprintf(stderr, "Error reading block 0x%llx\n",
				src_blk + i);
			repair_error = 1;
			break;
		}

		status = dmz_write_block(dev, dst_blk + i, (char *)block_buffer);

		if (status) {
			fprintf(stderr, "Error writing block 0x%llx\n",
				dst_blk + i);
			repair_error = 1;
			break;
		}

	}

repair_end:
	/* Flush before we go... */
	if (fsync(dev->fd) < 0) {
		fprintf(stderr, "%s: fsync failed %d (%s)\n",
			dev->name, errno, strerror(errno));
		repair_error = -1;
	}

	printf("Repair done\n");
	return repair_error;
}
