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

static const char modname[] = "dm-zoned";

int dmz_mod_ver;

/*
 * Print usage.
 */
static void dmzadm_usage(void)
{
	printf("Usage: dmzadm <operation> <device(s)> [options]\n");

	printf("Operations\n"
	       "  --version | -v : Print version number and exit\n"
	       "  --help | -h	 : General help message\n"
	       "  --format	 : Format a block device metadata\n"
	       "  --check	 : Check a block device metadata\n"
	       "  --repair	 : Repair a block device metadata\n"
	       "  --relabel	 : Change the device label\n"
	       "  --start	 : Start the device-mapper target\n"
	       "  --stop	 : Stop the device-mapper target\n");

	printf("Devices\n"
	       "  For a single device target, a zoned block device\n"
	       "  must be specified. For a multi-device target, a\n"
	       "  a list of block devices must be specified, with\n"
	       "  a regular block device as the first device specified,\n"
	       "  followed by one or more zoned block devices\n");

	printf("General options\n"
	       "  --verbose	: Verbose output\n"
	       "  --vverbose	: Very verbose output\n");

	printf("Format operation options\n"
	       "  --force	: Force overwrite of existing content\n"
	       "  --label=<str> : Set the target label name to <str>\n"
	       "  --seq=<num>	: Number of sequential zones reserved\n"
	       "                  for reclaim. The minimum is 1 and the\n"
	       "                  default is %d\n",
	       DMZ_NR_RESERVED_SEQ);

	printf("Relabel operation options\n"
	       "  --label=<str> : Set the target new label name to <str>\n");
}

void print_dev_info(struct dmz_block_dev *bdev)
{
	printf("%s: %llu 512-byte sectors (%llu GiB)\n",
	       bdev->path, bdev->capacity,
	       (bdev->capacity << 9) / (1024ULL * 1024ULL * 1024ULL));
	if (bdev->type == DMZ_TYPE_REGULAR)
		printf("  Regular block device\n");
	else
		printf("  Host-%s device\n",
		       (bdev->type == DMZ_TYPE_ZONED_HM) ? "managed" : "aware");
	printf("  %u zones, offset %llu\n", bdev->nr_zones, bdev->block_offset);
}

/*
 * Main function.
 */
int main(int argc, char **argv)
{
	unsigned int nr_zones;
	struct dmz_dev *dev;
	int i, ret, log_level = 0, optnum;
	enum dmz_op op;

	/* Parse operation */
	if (argc < 2) {
		dmzadm_usage();
		return 1;
	}

	if (strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "-h") == 0) {
		printf("dmzadm allows formatting, checking and repairing\n"
		       "a zoned block device for use with the dm-zoned\n"
		       "device mapper.\n");
		dmzadm_usage();
		return 0;
	}

	if (strcmp(argv[1], "--version") == 0 ||
	    strcmp(argv[1], "-v") == 0) {
		printf("%s\n", PACKAGE_VERSION);
		return 0;
	}

	if (strcmp(argv[1], "--format") == 0) {
		op = DMZ_OP_FORMAT;
	} else if (strcmp(argv[1], "--check") == 0) {
		op = DMZ_OP_CHECK;
	} else if (strcmp(argv[1], "--repair") == 0) {
		op = DMZ_OP_REPAIR;
	} else if (strcmp(argv[1], "--relabel") == 0) {
		op = DMZ_OP_RELABEL;
	} else if (strcmp(argv[1], "--start") == 0) {
		op = DMZ_OP_START;
	} else if (strcmp(argv[1], "--stop") == 0) {
		op = DMZ_OP_STOP;
	} else {
		fprintf(stderr,
			"Unknown operation \"%s\"\n",
			argv[1]);
		return 1;
	}

	if (argc < 3) {
		dmzadm_usage();
		return 1;
	}
	dev = malloc(sizeof(struct dmz_dev));
	if (!dev) {
		fprintf(stderr, "Cannot allocate device memory\n");
		return 1;
	}
	/* Initialize */
	memset(dev, 0, sizeof(struct dmz_dev));
	dev->nr_reserved_seq = DMZ_NR_RESERVED_SEQ;
	dev->sb_version = DMZ_META_VER;

	/* Get device paths */
	optnum = 2;
	for (i = optnum; i < argc; i++) {
		if (!strncmp(argv[i], "--", 2))
			break;
		optnum++;
	}
	dev->nr_bdev = optnum - 2;
	dev->bdev = malloc(sizeof(struct dmz_block_dev) * dev->nr_bdev);
	for (i = 0; i < dev->nr_bdev; i++) {
		dev->bdev[i].path = realpath(argv[i + 2], NULL);
		if (!dev->bdev[i].path) {
			fprintf(stderr, "Get device %s real path failed\n",
				argv[i + 2]);
			return 1;
		}
	}

	/* Parse arguments */
	for (i = optnum; i < argc; i++) {

		if (strcmp(argv[i], "--verbose") == 0) {

			dev->flags |= DMZ_VERBOSE;
			log_level = 1;

		} else if (strcmp(argv[i], "--vverbose") == 0) {

			dev->flags |= DMZ_VERBOSE | DMZ_VVERBOSE;
			log_level = 2;

		} else if (strncmp(argv[i], "--seq=", 6) == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--seq option is valid only with the "
					"format operation\n");
				return 1;
			}

			dev->nr_reserved_seq = atoi(argv[i] + 6);
			if (dev->nr_reserved_seq <= 0) {
				fprintf(stderr,
					"Invalid number of sequential zones\n");
				return 1;
			}

		} else if (strncmp(argv[i], "--label=", 8) == 0) {
			const char *label = argv[i] + 8;
			unsigned int label_size = strlen(label);

			if (op != DMZ_OP_FORMAT && op != DMZ_OP_RELABEL) {
				fprintf(stderr,
					"--label option is valid only with the "
					"format operation\n");
				return 1;
			}
			if (label[0] == '\'' || label[0] == '\"') {
				label++;
				label_size -= 2;
			}
			if (label_size > DMZ_LABEL_LEN - 1) {
				fprintf(stderr,
					"Label too long (max %d characters)\n",
					DMZ_LABEL_LEN - 1);
				return 1;
			}
			if (op == DMZ_OP_FORMAT)
				memcpy(dev->label, label, label_size);
			else
				memcpy(dev->new_label, label, label_size);

		} else if (strcmp(argv[i], "--force") == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--force option is valid only with the "
					"format operation\n");
				return 1;
			}

			dev->flags |= DMZ_OVERWRITE;

		} else if (argv[i][0] != '-') {

			break;

		} else {

			fprintf(stderr,
				"Unknown option \"%s\"\n",
				argv[i]);
			return 1;

		}

	}

	/* Load module if not present */
	ret = dmz_load_module(modname, log_level);
	if (ret)
		return 1;

	/* Check device-mapper target version */
	dmz_mod_ver = dmz_init_dm(log_level);
	if (dmz_mod_ver <= 0)
		return 1;

	if (dmz_mod_ver < (int)dev->sb_version) {
		fprintf(stderr, "Falling back to metadata version %d\n",
			dmz_mod_ver);
		dev->sb_version = dmz_mod_ver;
	} else if (dmz_mod_ver > (int)dev->sb_version) {
		printf("Defaulting to metadata version %d from version %d\n",
		       dev->sb_version, dmz_mod_ver);
	}
	if (op == DMZ_OP_STOP) {
		char holder[PATH_MAX];

		if (dmz_get_dev_holder(&dev->bdev[0], holder) < 0)
			return 1;
		if (!strlen(holder)) {
			fprintf(stderr, "%s: no dm-zoned device found\n",
				dev->bdev[0].name);
			return 1;
		}
		return dmz_stop(dev, holder);
	}

	/* Open the device */
	if (dmz_open_dev(&dev->bdev[0], op, dev->flags) < 0)
		return 1;
	if (dev->nr_bdev > 1) {
		if (dmz_bdev_is_zoned(&dev->bdev[0])) {
			fprintf(stderr,
				"%s: Not a regular block device\n",
				dev->bdev[0].name);
			dmz_close_dev(&dev->bdev[0]);
			return 1;
		}
	} else {
		if (!dmz_bdev_is_zoned(&dev->bdev[0])) {
			fprintf(stderr,
				"%s: Not a zoned block device\n",
				dev->bdev[0].name);
			dmz_close_dev(&dev->bdev[0]);
			return 1;
		}
		dev->zone_nr_sectors = dev->bdev[0].zone_nr_sectors;
		dev->zone_nr_blocks = dev->bdev[0].zone_nr_blocks;
	}
	dev->capacity = dev->bdev[0].capacity;

	for (i = 1; i < dev->nr_bdev; i++) {
		if (dmz_open_dev(&dev->bdev[i], op, dev->flags) < 0)
			return 1;
		if (!dmz_bdev_is_zoned(&dev->bdev[i])) {
			fprintf(stderr,
				"%s: Not a zoned block device\n",
				dev->bdev[i].name);
			ret = 1;
			goto out_close;
		}
		dev->capacity += dev->bdev[i].capacity;
		if (dev->zone_nr_sectors &&
		    dev->zone_nr_sectors != dev->bdev[i].zone_nr_sectors) {
			fprintf(stderr,
				"%s: zone_nr_sectors mismatch (%lu/%lu)\n",
				dev->bdev[i].name,
				dev->zone_nr_sectors,
				dev->bdev[i].zone_nr_sectors);
			ret = 1;
			goto out_close;
		} else
			dev->zone_nr_sectors = dev->bdev[i].zone_nr_sectors;
		if (dev->zone_nr_blocks &&
		    dev->zone_nr_blocks != dev->bdev[i].zone_nr_blocks) {
			fprintf(stderr,
				"%s: zone_nr_blocks mismatch (%lu/%lu)\n",
				dev->bdev[i].name,
				dev->zone_nr_blocks,
				dev->bdev[i].zone_nr_blocks);
			ret = 1;
			goto out_close;
		} else
			dev->zone_nr_blocks = dev->bdev[i].zone_nr_blocks;
	}
	if (dev->nr_bdev > 1) {
		__u64 block_offset = 0;

		dev->bdev[0].zone_nr_sectors = dev->zone_nr_sectors;
		dev->bdev[0].zone_nr_blocks = dev->zone_nr_blocks;
		dev->bdev[0].nr_zones =
			dev->bdev[0].capacity / dev->zone_nr_sectors;
		dev->bdev[0].block_offset = block_offset;
		if (dev->bdev[0].capacity % dev->zone_nr_sectors)
			dev->bdev[0].nr_zones++;
		block_offset = dev->bdev[0].nr_zones * dev->zone_nr_blocks;
		for (i = 1; i < dev->nr_bdev; i++) {
			dev->bdev[i].block_offset = block_offset;
			block_offset +=
				dev->bdev[i].nr_zones * dev->zone_nr_blocks;
		}
	}

	for (i = 0; i < dev->nr_bdev; i++)
		print_dev_info(&dev->bdev[i]);

	if (dmz_get_dev_zones(dev) < 0)
		return 1;

	nr_zones = dev->capacity / dev->zone_nr_sectors;
	printf("  %u zones of %zu 512-byte sectors (%zu MiB)\n",
	       nr_zones,
	       dev->zone_nr_sectors,
	       (dev->zone_nr_sectors << 9) / (1024 * 1024));
	if (nr_zones < dev->nr_zones) {
		size_t runt_sectors = dev->capacity & (dev->zone_nr_sectors - 1);

		printf("  1 runt zone of %zu 512-byte sectors (%zu MiB)\n",
		       runt_sectors,
		       (runt_sectors << 9) / (1024 * 1024));
	}
	printf("  %zu 4KB data blocks per zone\n",
	       dev->zone_nr_blocks);

	switch (op) {

	case DMZ_OP_FORMAT:
		ret = dmz_format(dev);
		break;

	case DMZ_OP_CHECK:
		ret = dmz_check(dev);
		break;

	case DMZ_OP_REPAIR:
		ret = dmz_repair(dev);
		break;

	case DMZ_OP_RELABEL:
		ret = dmz_relabel(dev);
		break;

	case DMZ_OP_START:
		ret = dmz_start(dev);
		break;

	default:

		fprintf(stderr, "Unknown operation\n");
		ret = 1;
		break;

	}

	free(dev->zones);
	dev->zones = NULL;
out_close:
	for (i = 0; i < dev->nr_bdev; i++)
		dmz_close_dev(&dev->bdev[i]);
	free(dev->bdev);
	free(dev);
	return ret;
}

