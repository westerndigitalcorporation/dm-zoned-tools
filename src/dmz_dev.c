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

/***** Including files *****/

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
#include <mntent.h>
#include <dirent.h>

/*
 * Test if the device is mounted.
 */
static int dmz_dev_mounted(struct dmz_dev *dev)
{
	struct mntent *mnt = NULL;
	FILE *file = NULL;

	file = setmntent("/proc/mounts", "r");
	if (file == NULL)
		return 0;

	while ((mnt = getmntent(file)) != NULL) {
		if (strcmp(dev->path, mnt->mnt_fsname) == 0)
			break;
	}
	endmntent(file);

	return mnt ? 1 : 0;
}

/*
 * Test if the device is already used as a target backend.
 */
static int dmz_dev_busy(struct dmz_dev *dev)
{
	char path[128];
	struct dirent **namelist;
	int n, ret = 0;

	snprintf(path, sizeof(path),
		 "/sys/block/%s/holders",
		 dev->name);

	n = scandir(path, &namelist, NULL, alphasort);
	if (n < 0) {
		fprintf(stderr, "scandir %s failed\n", path);
		return -1;
	}

	while (n--) {
		if (strcmp(namelist[n]->d_name, "..") != 0 &&
		    strcmp(namelist[n]->d_name, ".") != 0)
			ret = 1;
		free(namelist[n]);
	}
	free(namelist);

	return ret;
}

/*
 * Get a zoned block device model (host-aware or howt-managed).
 */
static int dmz_get_dev_model(struct dmz_dev *dev)
{
	char str[128];
	FILE *file;
	int res;

	/* Check that this is a zoned block device */
	snprintf(str, sizeof(str),
		 "/sys/block/%s/queue/zoned",
		 dev->name);
	file = fopen(str, "r");
	if (!file) {
		fprintf(stderr, "Open %s failed\n", str);
		return -1;
	}

	memset(str, 0, sizeof(str));
	res = fscanf(file, "%s", str);
	fclose(file);

	if (res != 1) {
		fprintf(stderr, "Invalid file %s format\n", str);
		return -1;
	}

	if (strcmp(str, "host-aware") == 0)
		dev->flags |= DMZ_ZONED_HA;
	else if (strcmp(str, "host-managed") == 0)
		dev->flags |= DMZ_ZONED_HM;

	return 0;
}

/*
 * Get device capacity and zone size.
 */
static int dmz_get_dev_capacity(struct dmz_dev *dev)
{
	char str[128];
	FILE *file;
	int res;

	/* Get capacity */
	if (ioctl(dev->fd, BLKGETSIZE64, &dev->capacity) < 0) {
		fprintf(stderr,
			"%s: Get capacity failed %d (%s)\n",
			dev->path, errno, strerror(errno));
		return -1;
	}
	dev->capacity >>= 9;

	/* Get zone size */
	snprintf(str, sizeof(str),
		 "/sys/block/%s/queue/chunk_sectors",
		 dev->name);
	file = fopen(str, "r");
	if (!file) {
		fprintf(stderr, "Open %s failed\n", str);
		return -1;
	}

	memset(str, 0, sizeof(str));
	res = fscanf(file, "%s", str);
	fclose(file);

	if (res != 1) {
		fprintf(stderr, "Invalid file %s format\n", str);
		return -1;
	}

	dev->zone_nr_sectors = atol(str);
	if (!dev->zone_nr_sectors ||
	    (dev->zone_nr_sectors & DMZ_BLOCK_SECTORS_MASK)) {
		fprintf(stderr,
			"%s: Invalid zone size\n",
			dev->path);
		return -1;
	}
	dev->zone_nr_blocks = dmz_sect2blk(dev->zone_nr_sectors);

	return 0;
}

/*
 * Print a device zone information.
 */
static void dmz_print_zone(struct dmz_dev *dev,
			   struct blk_zone *zone)
{

	if (dmz_zone_cond(zone) == BLK_ZONE_COND_READONLY) {
		printf("Zone %05u: readonly %s zone\n",
		       dmz_zone_id(dev, zone),
		       dmz_zone_cond_str(zone));
		return;
	}

	if (dmz_zone_cond(zone) == BLK_ZONE_COND_OFFLINE) {
		printf("Zone %05u: offline %s zone\n",
		       dmz_zone_id(dev, zone),
		       dmz_zone_cond_str(zone));
		return;
	}

	if (dmz_zone_conv(zone)) {
		printf("Zone %05u: Conventional, cond 0x%x (%s), "
		       "sector %llu, %llu sectors\n",
		       dmz_zone_id(dev, zone),
		       dmz_zone_cond(zone),
		       dmz_zone_cond_str(zone),
		       dmz_zone_sector(zone),
		       dmz_zone_length(zone));
		return;
	}

	printf("Zone %05u: type 0x%x (%s), cond 0x%x (%s), need_reset %d, "
	       "non_seq %d, sector %llu, %llu sectors, wp sector %llu\n",
	       dmz_zone_id(dev, zone),
	       dmz_zone_type(zone),
	       dmz_zone_type_str(zone),
	       dmz_zone_cond(zone),
	       dmz_zone_cond_str(zone),
	       dmz_zone_need_reset(zone),
	       dmz_zone_non_seq(zone),
	       dmz_zone_sector(zone),
	       dmz_zone_length(zone),
	       dmz_zone_wp_sector(zone));
}

#define DMZ_REPORT_ZONES_BUFSZ	524288

/*
 * Get a device zone configuration.
 */
static int dmz_get_dev_zones(struct dmz_dev *dev)
{
	struct blk_zone_report *rep = NULL;
	unsigned int rep_max_zones;
	struct blk_zone *blkz;
	unsigned int i, nr_zones;
	__u64 sector;
	int ret = -1;

	/* This will ignore an eventual last smaller zone */
	nr_zones = dev->capacity / dev->zone_nr_sectors;
	if (dev->capacity % dev->zone_nr_sectors)
		nr_zones++;

	/* Allocate zone array */
	dev->zones = calloc(nr_zones, sizeof(struct blk_zone));
	if (!dev->zones) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}

	/* Get a buffer for zone report */
	rep = malloc(DMZ_REPORT_ZONES_BUFSZ);
	if (!rep) {
		fprintf(stderr, "Not enough memory\n");
		goto out;
	}
	rep_max_zones =
		(DMZ_REPORT_ZONES_BUFSZ - sizeof(struct blk_zone_report))
		/ sizeof(struct blk_zone);

	sector = 0;
	while (sector < dev->capacity) {

		/* Get zone information */
		memset(rep, 0, DMZ_REPORT_ZONES_BUFSZ);
		rep->sector = sector;
		rep->nr_zones = rep_max_zones;
		ret = ioctl(dev->fd, BLKREPORTZONE, rep);
		if (ret != 0) {
			fprintf(stderr,
				"%s: Get zone information failed %d (%s)\n",
				dev->name, errno, strerror(errno));
			goto out;
		}

		if (!rep->nr_zones)
			break;

		blkz = (struct blk_zone *)(rep + 1);
		for (i = 0; i < rep->nr_zones && sector < dev->capacity; i++) {

			if (dev->flags & DMZ_VVERBOSE)
				dmz_print_zone(dev, blkz);

			/* Check zone size */
			if (dmz_zone_length(blkz) != dev->zone_nr_sectors &&
			    dmz_zone_sector(blkz) + dmz_zone_length(blkz) != dev->capacity) {
				fprintf(stderr,
					"%s: Invalid zone %u size\n",
					dev->name,
					dmz_zone_id(dev, blkz));
				ret = -1;
				goto out;
			}

			dev->zones[dev->nr_zones] = *blkz;
			dev->nr_zones++;

			sector = dmz_zone_sector(blkz) + dmz_zone_length(blkz);
			blkz++;

		}

	}

	if (sector != dev->capacity) {
		fprintf(stderr,
			"%s: Invalid zones (last sector reported is %llu, "
			"expected %llu)\n",
			dev->name,
			sector, dev->capacity);
		ret = -1;
		goto out;
	}

	if (dev->nr_zones != nr_zones) {
		fprintf(stderr,
			"%s: Invalid number of zones (expected %u, got %u)\n",
			dev->name,
			nr_zones, dev->nr_zones);
		ret = -1;
		goto out;
	}

out:
	if (rep)
		free(rep);
	if (ret != 0)
		free(dev->zones);

	return ret;
}

/*
 * Get a device information.
 */
static int dmz_get_dev_info(struct dmz_dev *dev)
{

	if (dmz_get_dev_model(dev) < 0)
		return -1;

	if (!dmz_dev_is_zoned(dev)) {
		fprintf(stderr,
			"%s: Not a zoned block device\n",
			dev->name);
		return -1;
	}

	if (dmz_get_dev_capacity(dev) < 0)
		return -1;

	if (dmz_get_dev_zones(dev) < 0)
		return -1;

	return 0;
}

/*
 * Open a device.
 */
int dmz_open_dev(struct dmz_dev *dev)
{
	struct stat st;

	dev->name = basename(dev->path);

	/* Check that this is a block device */
	if (stat(dev->path, &st) < 0) {
		fprintf(stderr,
			"Get %s stat failed %d (%s)\n",
			dev->path,
			errno, strerror(errno));
		return -1;
	}

	if (!S_ISBLK(st.st_mode)) {
		fprintf(stderr,
			"%s is not a block device\n",
			dev->path);
		return -1;
	}

	if (dmz_dev_mounted(dev)) {
		fprintf(stderr,
			"%s is mounted\n",
			dev->path);
		return -1;
	}

	if (dmz_dev_busy(dev)) {
		fprintf(stderr,
			"%s is in use\n",
			dev->path);
		return -1;
	}

	/* Open device */
	dev->fd = open(dev->path, O_RDWR | O_LARGEFILE);
	if (dev->fd < 0) {
		fprintf(stderr,
			"Open %s failed %d (%s)\n",
			dev->path,
			errno, strerror(errno));
		return -1;
	}

	/* Get device capacity and zone configuration */
	if (dmz_get_dev_info(dev) < 0) {
		dmz_close_dev(dev);
		return -1;
	}

	return 0;
}

/*
 * Close an open device.
 */
void dmz_close_dev(struct dmz_dev *dev)
{
	if (dev->fd >= 0)
		close(dev->fd);

	if(dev->zones)
		free(dev->zones);
}

/*
 * Reset a zone.
 */
int dmz_reset_zone(struct dmz_dev *dev,
		   struct blk_zone *zone)
{
	struct blk_zone_range range;

	if (dmz_zone_conv(zone) ||
	    dmz_zone_empty(zone))
		return 0;

	/* Non empty sequential zone: reset */
	range.sector = dmz_zone_sector(zone);
	range.nr_sectors = dmz_zone_length(zone);
	if (ioctl(dev->fd, BLKRESETZONE, &range) < 0) {
		fprintf(stderr,
			"%s: Reset zone %u failed %d (%s)\n",
			dev->name,
			dmz_zone_id(dev, zone),
			errno, strerror(errno));
		return -1;
	}

	zone->wp = zone->start;

	return 0;
}



/*
 * Reset all zones of a device.
 */
int dmz_reset_zones(struct dmz_dev *dev)
{
	unsigned int i;

	for (i = 0; i < dev->nr_zones; i++) {
		if (dmz_reset_zone(dev, &dev->zones[i]) < 0)
			return -1;
	}

	return 0;
}

int dmz_write_block(struct dmz_dev *dev, __u64 block, char *buf)
{
	ssize_t ret;

	ret = pwrite(dev->fd,
		     buf,
		     DMZ_BLOCK_SIZE, block << DMZ_BLOCK_SHIFT);
	if (ret != DMZ_BLOCK_SIZE) {
		fprintf(stderr,
			"%s: Write block %llu failed %d (%s)\n",
			dev->name,
			block,
			errno, strerror(errno));
		return -1;
	}

	return 0;
}
