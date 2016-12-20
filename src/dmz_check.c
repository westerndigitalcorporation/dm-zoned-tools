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

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static void calc_dmz_meta_data_loc(struct dmz_dev *dev, 
				   unsigned int *max_nr_meta_zones,
				   __u32 *nr_active_zones)
{
	struct blk_zone *zone;
	
	unsigned int i, last_meta_zone = 0;
	*nr_active_zones = 0;

	/* Count useable zones */
	for (i = 0; i < dev->nr_zones; i++) {

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
				last_meta_zone = i;
				*max_nr_meta_zones = 1;
			} else if (last_meta_zone == (i - 1)) {
				last_meta_zone = i;
				(*max_nr_meta_zones)++;
			}
		}

	}

	assert(dev->sb_zone);
	dev->sb_block = dmz_sect2blk(dmz_zone_sector(dev->sb_zone));
}




static int check_superblock(struct dmz_dev *dev, __u32 nr_zones,
			    __u8 *block_buffer, __u64 address,
			    int print_error)
{
	struct dm_zoned_super *sb;
	__u32 stored_crc, calculated_crc;

	sb = (struct dm_zoned_super *) block_buffer;

	/* First, check magic */
	if(__le32_to_cpu(sb->magic) != DMZ_MAGIC) {
		if(print_error)
			fprintf(stderr, 
			"Super block at 0x%llx failed magic check expect 0x%x read 0x%x\n",
			address, DMZ_MAGIC, __le32_to_cpu(sb->magic));
		
		return -1;
	}

	/* Now lets check the CRC */
	stored_crc = __le32_to_cpu(sb->crc);
	sb->crc = 0;

	calculated_crc = dmz_crc32(sb->gen, block_buffer, DMZ_BLOCK_SIZE);

	if(calculated_crc != stored_crc) {
		if(print_error)
			fprintf(stderr, 
			"Super block at 0x%llx failed crc check, expect 0x%x read 0x%x\n",
			address, calculated_crc, stored_crc);
		
		return -1;
	}


	/* Finally, the version */
	if(__le32_to_cpu(sb->version) != DMZ_META_VER) {
		if(print_error)
			fprintf(stderr,
			"Super block at 0x%llx failed version check, expect 0x%x read 0x%x\n", 
			address, DMZ_META_VER, __le32_to_cpu(sb->version));
		return -1;
	}

	if(__le64_to_cpu(sb->sb_block) != address) {
		if(print_error) 
			fprintf(stderr,
			"Super block at 0x%llx failed location check, expect 0x%llx read 0x%llx\n", 
			address, address, __le64_to_cpu(sb->sb_block));

		return -1;
	}

	/* Check total number of metadata blocks are expected */
	__u64 expected_nr_meta_blocks = 1 + __le32_to_cpu(sb->nr_map_blocks) + 
		__le32_to_cpu(sb->nr_bitmap_blocks);
	if(__le64_to_cpu(sb->nr_meta_blocks) != expected_nr_meta_blocks) {
		if(print_error) 
			fprintf(stderr,
			"Super block at 0x%llx failed number of metadata blocks check, expect 0x%llx read 0x%llx\n", 
			address, expected_nr_meta_blocks, __le64_to_cpu(sb->nr_meta_blocks));

		return -1;
	}

	__u32 nr_meta_zones = DIV_ROUND_UP(expected_nr_meta_blocks, dev->zone_nr_blocks);

	/* Check to make number of chunks is as expected */
	__u32 expected_nr_chunks = nr_zones - ((nr_meta_zones * 2) + __le32_to_cpu(sb->nr_reserved_seq));
	if(__le32_to_cpu(sb->nr_chunks) != expected_nr_chunks) {
		if(print_error) 
			fprintf(stderr,
			"Super block at 0x%llx failed number of chunks check, expect 0x%x read 0x%x\n", 
			address, expected_nr_chunks, __le32_to_cpu(sb->nr_chunks));

		return -1;
	}
	
	/* Check to make sure nr_chunks matches nr_map_blocks */
	__u32 expected_nr_map_blocks = DIV_ROUND_UP(__le32_to_cpu(sb->nr_chunks), DMZ_MAP_ENTRIES);
	if(__le32_to_cpu(sb->nr_map_blocks) != expected_nr_map_blocks) {
		if(print_error) 
			fprintf(stderr,
			"Super block at 0x%llx failed number of map blocks, expect 0x%x read 0x%x\n", 
			address, expected_nr_map_blocks, __le32_to_cpu(sb->nr_map_blocks));

		return -1;
	}

	/* Check to make sure # of zones match # of zone bitmap blocks */
	size_t zone_nr_bitmap_blocks = dev->zone_nr_blocks >> (DMZ_BLOCK_SHIFT + 3);
	__u32 expected_nr_bitmap_blocks = dev->nr_zones * zone_nr_bitmap_blocks;
	
	if(__le32_to_cpu(sb->nr_bitmap_blocks) != expected_nr_bitmap_blocks) {
		if(print_error) 
			fprintf(stderr,
			"Super block at 0x%llx failed number of bitmap blocks check, expect 0x%x read 0x%x\n", 
			address, expected_nr_bitmap_blocks, __le32_to_cpu(sb->nr_bitmap_blocks));

		return -1;
	}


	printf("Super block at 0x%llx with gen number %llu passed check\n", 
		address, __le64_to_cpu(sb->gen));

	return 0;
}

static int matching_superblock(struct dm_zoned_super *sb_0, struct dm_zoned_super *sb_1)
{
	if((sb_0->nr_meta_blocks == sb_1->nr_meta_blocks) &&
	(sb_0->nr_reserved_seq == sb_1->nr_reserved_seq) &&
	(sb_0->nr_chunks == sb_1->nr_chunks) &&
	(sb_0->nr_map_blocks == sb_1->nr_map_blocks) &&
	(sb_0->nr_bitmap_blocks == sb_1->nr_bitmap_blocks))
		return 1;

	return 0;
}


static int read_zone_bitmap(struct dmz_dev *dev, unsigned int zone_id,
			    __u64 bitmap_block, size_t zone_nr_bitmap_blocks,
			    __u8 *buf, __u64 *bitmap_block_address)
{
	__u64 starting_block = bitmap_block + (zone_id * zone_nr_bitmap_blocks);
	*bitmap_block_address = starting_block;
	int status;

	for(unsigned int i = 0; i < zone_nr_bitmap_blocks; i++) {
		__u64 block = starting_block + i;
		char *c_ptr = (char *)(buf + (i * DMZ_BLOCK_SIZE));

		status = dmz_read_block(dev, block, c_ptr);

		if(status) {
			fprintf(stderr, "Error reading bitmap block at 0x%llx\n", block);
			return -1;
		}
	}

	return 0;
}

static int check_zone_mapping_and_bitmap(struct dmz_dev *dev, __u64 sb_address,
					 struct dm_zoned_super *sb, int repair)
{
	__u8 map_block_buffer[DMZ_BLOCK_SIZE];

	__u64 map_block;
	__u32 nr_map_blocks;

	__u64 bitmap_block;
	__u32 nr_bitmap_blocks;

	int status;

	__u8 map_zone_entry_bitmap[DIV_ROUND_UP(dev->nr_zones, 8)];

	size_t zone_nr_bitmap_blocks;

	int found_error = 0;


	map_block = sb_address + 1;	
	nr_map_blocks = __le32_to_cpu(sb->nr_map_blocks);

	for(unsigned int i = 0; i < DIV_ROUND_UP(dev->nr_zones, 8); i++) {
		map_zone_entry_bitmap[i] = 0;
	}

	printf("Starting mapping table verification at 0x%llx for %u blocks\n",
		map_block, nr_map_blocks);

	for (unsigned int i = 0; i < nr_map_blocks; i++) {
		status = dmz_read_block(dev, map_block + i, (char *)map_block_buffer);

		if(status) {
			fprintf(stderr, "Error reading map block at 0x%llx\n", map_block + i);
			found_error = 1;
		} else {
			/* Lets do mapping check in multiple rounds, this will make the logic cleaner but less efficient */
			struct dm_zoned_map *dmap;
			int valid_zone_ids = 1;
			
			/* First, lets make sure the zone ids are valid and that there are no redundant mappings */
			dmap = (struct dm_zoned_map *)map_block_buffer;
			
			for(unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
				__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
				__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);
				int invalid_dzone_id = 0;
				int invalid_bzone_id = 0;

				if((dzone_id != DMZ_MAP_UNMAPPED) && (dzone_id >= dev->nr_zones)) {
					fprintf(stderr, "Invalid dzone id 0x%x for mapping entry 0x%x\n", dzone_id, j);
					invalid_dzone_id = 1;
				}

				if((bzone_id != DMZ_MAP_UNMAPPED) && (bzone_id >= dev->nr_zones)) {
					fprintf(stderr, "Invalid bzone id 0x%x for mapping entry 0x%x\n", bzone_id, j);
					invalid_bzone_id = 1;
				}

				if(invalid_dzone_id || invalid_bzone_id) {
					valid_zone_ids = 0;
					continue;
				}

				/* Check for redundant zone mapping */
				if(dzone_id != DMZ_MAP_UNMAPPED) {
					int element_idx = dzone_id / 8;
					int bit_idx = (dzone_id % 8);

					/* Check if zone bit is set */
					if(map_zone_entry_bitmap[element_idx] & (1 << bit_idx)) {
						fprintf(stderr, 
							"Error found repeat zone id 0x%x as dzone for mapping entry 0x%x\n", 
							dzone_id, j);
						valid_zone_ids = 0;
					} else {
						/* Set the bit */
						map_zone_entry_bitmap[element_idx] |= (1 << bit_idx);
					}
				}

				/* Check for redundant zone mapping */
				if(bzone_id != DMZ_MAP_UNMAPPED) {
					int element_idx = bzone_id / 8;
					int bit_idx = (bzone_id % 8);

					/* Check if zone bit is set */
					if(map_zone_entry_bitmap[element_idx] & (1 << bit_idx)) {
						fprintf(stderr, 
							"Error found repeat zone id 0x%x as bzone for mapping entry 0x%x\n", 
							bzone_id, j);
						valid_zone_ids = 0;
					} else {
						/* Set the bit */
						map_zone_entry_bitmap[element_idx] |= (1 << bit_idx);
					}
				}
			}

			if(!valid_zone_ids) {
				fprintf(stderr, "Found invalid zone ids in mapping\n");
				found_error = 1;
			}

			/* Now, lets make sure the zone ids are used as intended */
			dmap = (struct dm_zoned_map *)map_block_buffer;

			for(unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
				__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
				__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);

				if((dzone_id != DMZ_MAP_UNMAPPED) && (dzone_id >= dev->nr_zones)) {
					continue;
				}

				if((bzone_id != DMZ_MAP_UNMAPPED) && (bzone_id >= dev->nr_zones)) {
					continue;
				}

				/* Bzone should not be squential only zone */
				if(bzone_id != DMZ_MAP_UNMAPPED) {
					struct blk_zone *bzone = &dev->zones[bzone_id];

					if(!dmz_zone_rnd(bzone)) {
						fprintf(stderr, 
							"Invalid bzone mapping (0x%x) to a non-random writable zone for mapping entry 0x%x\n", 
							bzone_id, j);
						found_error = 1;
					}
				}

				if(dzone_id == DMZ_MAP_UNMAPPED) {
					/* If dzone is not mapped then we expect bzone to be not mapped as well */
					if(bzone_id != DMZ_MAP_UNMAPPED) {
						fprintf(stderr, 
							"Unexpected bzone mapping (0x%x) as dzone is unmapped for mapping entry 0x%x\n", 
							bzone_id, j);
						found_error = 1;
					}
					/* To do: write DMZ_MAP_UNMAPPED for bzone_id */
				} else {
					struct blk_zone *dzone = &dev->zones[dzone_id];
					
					if(dmz_zone_rnd(dzone)) {
						/* If dzone is random, then no need for bzone*/
						if(bzone_id != DMZ_MAP_UNMAPPED) {
							fprintf(stderr, 
								"Unexpected bzone mapping (0x%x) as dzone is random writable for mapping entry 0x%x\n", 
								bzone_id, j);
							found_error = 1;
						}
					}

					if(dmz_zone_seq_req(dzone)) {
						/* Zone should not be empty */
						if(dmz_zone_empty(dzone)) {
							fprintf(stderr, 
								"Warning, dzone (0x%x) is empty for mapping entry 0x%x\n", 
								dzone_id, j);
							found_error = 1;
						}
					}
				}
			}
		}
	}
	
	printf("Mapping table verification complete\n");

	bitmap_block = map_block + nr_map_blocks;
	nr_bitmap_blocks = __le32_to_cpu(sb->nr_bitmap_blocks);
	zone_nr_bitmap_blocks = dev->zone_nr_blocks >> (DMZ_BLOCK_SHIFT + 3);

	printf("Starting zone bitmaps verification at 0x%llx for %u blocks\n", 
		bitmap_block, nr_bitmap_blocks);

	/* Again, let's do the check in multiple loops... */
	
	__u8 zone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];

	/* First, make sure the bitmaps for seq zones are correct (set bits must be less than WP) */
	for (unsigned int i = 0; i < dev->nr_zones; i++) {
		struct blk_zone *zone = &dev->zones[i];
		__u64 bitmap_block_address;
		
		if(!dmz_zone_seq_req(zone))
			continue;

		/* Read in the zone bits */
		if(read_zone_bitmap(dev, i, bitmap_block, zone_nr_bitmap_blocks, 
			zone_bitmap_buffer, &bitmap_block_address))
			continue;

		assert(zone->wp >= dmz_zone_sector(zone));

		__u64 wp_sect_offset = zone->wp - dmz_zone_sector(zone);

		assert((wp_sect_offset % (1 << DMZ_BLOCK_SECTORS_SHIFT)) == 0);

		__u64 wp_block = dmz_sect2blk(wp_sect_offset);

		/* No bits should be set >= WP */
		for (unsigned int j = wp_block; j < dev->zone_nr_blocks; j++) {
			int element_idx = j / 8;
			int bit_idx = (j % 8);

			assert (element_idx < (int)(zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE));

			if(zone_bitmap_buffer[element_idx] & (1 << bit_idx)) {
				fprintf(stderr, 
					"Error in zone bit map, valid bits after zone wp. Zone %u at block offset %u in bit block 0x%llx\n", 
					i, j, bitmap_block_address);
				found_error = 1;
			}
		}
	}

	/* Now we make sure there are no overlaps between a dzone's bitmap and its associated bzone's bitmap */

	for (unsigned int i = 0; i < nr_map_blocks; i++) {
		status = dmz_read_block(dev, map_block + i, (char *)map_block_buffer);

		if(status) {
			fprintf(stderr, "Error reading map block at 0x%llx\n", map_block + i);
			found_error = 1;
		} else {
			struct dm_zoned_map *dmap;
			
			dmap = (struct dm_zoned_map *)map_block_buffer;
			
			for(unsigned int j = 0; j < DMZ_MAP_ENTRIES; dmap++, j++) {
				__u32 dzone_id = __le32_to_cpu(dmap->dzone_id);
				__u32 bzone_id = __le32_to_cpu(dmap->bzone_id);

				if((dzone_id == DMZ_MAP_UNMAPPED) || (bzone_id == DMZ_MAP_UNMAPPED))
					continue;

				assert ((dzone_id != DMZ_MAP_UNMAPPED) && (bzone_id != DMZ_MAP_UNMAPPED));

				__u8 dzone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];
				__u8 bzone_bitmap_buffer[zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE];
				__u64 dzone_bitmap_block_address;
				__u64 bzone_bitmap_block_address;

				/* Read in the zone bits */
				if(read_zone_bitmap(dev, dzone_id, bitmap_block, 
					zone_nr_bitmap_blocks, dzone_bitmap_buffer, 
					&dzone_bitmap_block_address))
					continue;

				if(read_zone_bitmap(dev, bzone_id, bitmap_block, 
					zone_nr_bitmap_blocks, bzone_bitmap_buffer, 
					&bzone_bitmap_block_address))
					continue;

				/* Make sure there are no overlaps */
				for(unsigned int k = 0; k < zone_nr_bitmap_blocks * DMZ_BLOCK_SIZE; k++) {
					if(dzone_bitmap_buffer[k] & bzone_bitmap_buffer[k]) {
						fprintf(stderr, "Error in zone bit maps, overlap between dzone and bzone.\n");
						fprintf(stderr, "dzone %u at block offset %u in bit block 0x%llx with value 0x%x\n",
							dzone_id, k, dzone_bitmap_block_address, dzone_bitmap_buffer[k]);
						fprintf(stderr, "bzone %u at block offset %u in bit block 0x%llx with value 0x%x\n",
							bzone_id, k, bzone_bitmap_block_address, bzone_bitmap_buffer[k]);

						found_error = 1;
					}
				}
			}
		}
	}

	printf("Zone bitmaps verification complete\n");

	if(found_error)
		printf("Found errors in metadata blocks in range 0x%llx to 0x%llx\n", 
			map_block, bitmap_block + nr_bitmap_blocks - 1);
	else
		printf("No errors found in metadata blocks in range 0x%llx to 0x%llx\n", 
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
	__u64 sb_gen[2] = {0};
	int status;
	unsigned int max_nr_meta_zones = 0;
	unsigned int i;
	unsigned int sb_index_to_use;
	__u32 nr_active_zones = 0;
	
	calc_dmz_meta_data_loc(dev, &max_nr_meta_zones, &nr_active_zones);


	sb_address[0] = dev->sb_block;

	status = dmz_read_block(dev, sb_address[0], (char *)sb_block_buffer[0]);
	
	if(status) {
		fprintf(stderr, 
			"Error reading super block at 0x%llx\n",
			sb_address[0]);
	} else {
		status = check_superblock(dev, nr_active_zones, 
				sb_block_buffer[0], sb_address[0], 1);

		if(!status)
			valid_sb[0] = 1;
	}
	
	if(valid_sb[0]) {
		/* We've got a good sb[0], now lets calculate location of sb[1] */
		struct dm_zoned_super *sb = 
			(struct dm_zoned_super *) sb_block_buffer[0];
		
		dev->nr_meta_zones = 
			DIV_ROUND_UP(sb->nr_meta_blocks, dev->zone_nr_blocks);
		
		sb_address[1] = 
			sb_address[0] + (dev->nr_meta_zones * dev->zone_nr_blocks);

		status = dmz_read_block(dev, sb_address[1], 
			(char *)sb_block_buffer[1]);

		if(status) {
			fprintf(stderr, 
				"Error reading super block at 0x%llx\n", 
				sb_address[1]);
		} else {
			status = check_superblock(dev, nr_active_zones, 
				sb_block_buffer[1], sb_address[1], 1);

			if(!status)
				valid_sb[1] = 1;
		}

	} else {
		/* We've don't have a good sb[0], now lets find location of sb[1] */

		sb_address[1] = sb_address[0] + dev->zone_nr_blocks;

		printf("Searching for super block\n");
		for (i = 0; i < max_nr_meta_zones - 1; i++) {
			printf("At 0x%llx\n", sb_address[1]);

			status = dmz_read_block(dev, sb_address[1], 
				(char *)sb_block_buffer[1]);
			
			if(!status) {
				status = check_superblock(dev, nr_active_zones, 
					sb_block_buffer[1], sb_address[1], 0);
				
				if(!status) {
					valid_sb[1] = 1;
					break;
				}
			}

			sb_address[1] += dev->zone_nr_blocks;
		}
	}

	/* We've got no valid super block... */
	if(!valid_sb[0] && !valid_sb[1]) {
		fprintf(stderr, "No valid superblock found\n");
		/* To do: call format? */
		return -1;
	}

	/* Both super blocks are valid */
	if(valid_sb[0] && valid_sb[1]) {
		struct dm_zoned_super *sb_0 = 
			(struct dm_zoned_super *) sb_block_buffer[0];
		struct dm_zoned_super *sb_1 = 
			(struct dm_zoned_super *) sb_block_buffer[1];

		sb_gen[0] = __le64_to_cpu(sb_0->gen);
		sb_gen[1] = __le64_to_cpu(sb_1->gen);

		if(sb_gen[0] != sb_gen[1] ) {
			fprintf(stderr, 
				"Warning, generation number of the two super blocks do not match.\n");
		}

		if(!matching_superblock(sb_0, sb_1)) {
			fprintf(stderr, "Warning, the contents of two super blocks do not match.\n");
		}
	} 

	if(valid_sb[0]) {
		status = check_zone_mapping_and_bitmap(dev, sb_address[0], 
			(struct dm_zoned_super *) sb_block_buffer[0], 0);

		if(!status)
			valid_md_blocks[0] = 1;
		else
			valid_md_blocks[0] = 0;
	} else {
		valid_md_blocks[0] = 0;
	}

	if(valid_sb[1]) {
		status = check_zone_mapping_and_bitmap(dev, sb_address[1], 
			(struct dm_zoned_super *) sb_block_buffer[1], 0);

		if(!status)
			valid_md_blocks[1] = 1;
		else
			valid_md_blocks[1] = 0;
	} else {
		valid_md_blocks[1] = 0;
	}

	printf("Checking done\n");

	if(!repair)
		return 0;


	/* Repair operation starts below*/

	/* We've got no valid metadata blocks... */
	if(!valid_md_blocks[0] && !valid_md_blocks[1]) {
		fprintf(stderr, "Two sets of invalid metadata blocks\n");
		/* Lets try to repair one set of the md blocks and then do copy */

		sb_index_to_use = 0;
	} else {
		/* If both sets of md are good, then we are done */
		if(valid_md_blocks[0] && valid_md_blocks[1])
			return 0;

		/* If one of the md set is bad, then copy the good one over */
		
		/* Only a single set of valid md blocks */
		assert((valid_md_blocks[0] && !valid_md_blocks[1]) ||
			(!valid_md_blocks[0] && valid_md_blocks[1]));

		if(valid_md_blocks[0])
			sb_index_to_use = 0;
		else 
			sb_index_to_use = 1;
	}

	assert (1 >= sb_index_to_use);

	printf("Using superblock %d at address 0x%llxx as reference\n", 
		sb_index_to_use, sb_address[sb_index_to_use]);

	/* Only overwrite the other set of metadata if needed! */


	return 0;
}

