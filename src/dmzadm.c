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

/*
 * Print usage.
 */
static void dmzadm_usage(void)
{
	printf("Usage: dmzadm <operation> <device path> [options]\n");
	printf("Operations\n"
	       "  --help | -h	: General help message\n"
	       "  --format	: Format a block device metadata\n"
	       "  --check	: Check a block device metadata\n"
	       "  --repair	: Repair a block device metadata\n"
	       "  --start	: Start the device-mapper target\n"
	       "  --stop	: Stop the device-mapper target\n");

	printf("General options\n"
	       "  --verbose	: Verbose output\n"
	       "  --vverbose	: Very verbose output\n");

	printf("Format operation options\n"
	       "  --force	: Force overwrite of existing content\n"
	       "  --label=<str> : Set the name to <str>\n"
	       "  --seq=<num>	: Number of sequential zones reserved\n"
	       "                  for reclaim. The minimum is 1 and the\n"
	       "                  default is %d\n",
	       DMZ_NR_RESERVED_SEQ);
}

void print_dev_info(struct dmz_block_dev *bdev)
{
	printf("%s: %llu 512-byte sectors (%llu GiB)\n",
	       bdev->path, bdev->capacity,
	       (bdev->capacity << 9) / (1024ULL * 1024ULL * 1024ULL));
	printf("  Host-%s device\n",
	       (bdev->type == DMZ_TYPE_ZONED_HM) ? "managed" : "aware");

}

/*
 * Main function.
 */
int main(int argc, char **argv)
{
	unsigned int nr_zones;
	struct dmz_dev dev;
	int i, ret, log_level = 0, optnum;
	enum dmz_op op;

	/* Initialize */
	memset(&dev, 0, sizeof(dev));
	dev.bdev[0].fd = -1;
	dev.nr_reserved_seq = DMZ_NR_RESERVED_SEQ;
	dev.sb_version = DMZ_META_VER;

	/* Parse operation */
	if (argc < 2 ||
	    strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "-h") == 0) {
		printf("dmzadm allows formatting, checking and repairing\n"
		       "a zoned block device for use with the dm-zoned\n"
		       "device mapper.\n");
		dmzadm_usage();
		return 0;
	}

	if (strcmp(argv[1], "--format") == 0) {
		op = DMZ_OP_FORMAT;
	} else if (strcmp(argv[1], "--check") == 0) {
		op = DMZ_OP_CHECK;
	} else if (strcmp(argv[1], "--repair") == 0) {
		op = DMZ_OP_REPAIR;
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

	/* Get device path */
	dev.bdev[0].path = argv[2];
	optnum = 3;

	/* Parse arguments */
	for (i = optnum; i < argc; i++) {

		if (strcmp(argv[i], "--verbose") == 0) {

			dev.flags |= DMZ_VERBOSE;
			log_level = 1;

		} else if (strcmp(argv[i], "--vverbose") == 0) {

			dev.flags |= DMZ_VERBOSE | DMZ_VVERBOSE;
			log_level = 2;

		} else if (strncmp(argv[i], "--seq=", 6) == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--seq option is valid only with the "
					"format operation\n");
				return 1;
			}

			dev.nr_reserved_seq = atoi(argv[i] + 6);
			if (dev.nr_reserved_seq <= 0) {
				fprintf(stderr,
					"Invalid number of sequential zones\n");
				return 1;
			}

		} else if (strncmp(argv[i], "--label=", 8) == 0) {
			const char *label = argv[i] + 8;
			unsigned int label_size = strlen(label);

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--label option is valid only with the "
					"format operation\n");
				return 1;
			}
			if (label[0] == '\'' || label[0] == '\"') {
				label++;
				label_size -= 2;
			}
			if (label_size > 31) {
				fprintf(stderr,
					"Label too long (max 16 characters)\n");
				return 1;
			}
			memcpy(dev.label, label, label_size);

		} else if (strcmp(argv[i], "--force") == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--force option is valid only with the "
					"format operation\n");
				return 1;
			}

			dev.flags |= DMZ_OVERWRITE;

		} else if (argv[i][0] != '-') {

			break;

		} else {

			fprintf(stderr,
				"Unknown option \"%s\"\n",
				argv[i]);
			return 1;

		}

	}

	/* Check device-mapper target version */
	ret = dmz_init_dm(log_level);
	if (ret <= 0)
		return 1;

	if (op == DMZ_OP_STOP) {
		char holder[PATH_MAX];

		if (dmz_get_dev_holder(&dev.bdev[0], holder) < 0)
			return 1;
		if (!strlen(holder)) {
			fprintf(stderr, "%s: no dm-zoned device found\n",
				dev.bdev[0].name);
			return 1;
		}
		return dmz_stop(&dev, holder);
	}

	/* Open the device */
	if (dmz_open_dev(&dev.bdev[0], op, dev.flags) < 0)
		return 1;

	print_dev_info(&dev.bdev[0]);
	dev.capacity = dev.bdev[0].capacity;
	dev.zone_nr_sectors = dev.bdev[0].zone_nr_sectors;
	dev.zone_nr_blocks = dev.bdev[0].zone_nr_blocks;

	if (dmz_get_dev_zones(&dev) < 0)
		return 1;

	nr_zones = dev.capacity / dev.zone_nr_sectors;
	printf("  %u zones of %zu 512-byte sectors (%zu MiB)\n",
	       nr_zones,
	       dev.zone_nr_sectors,
	       (dev.zone_nr_sectors << 9) / (1024 * 1024));
	if (nr_zones < dev.nr_zones) {
		size_t runt_sectors = dev.capacity & (dev.zone_nr_sectors - 1);

		printf("  1 runt zone of %zu 512-byte sectors (%zu MiB)\n",
		       runt_sectors,
		       (runt_sectors << 9) / (1024 * 1024));
	}
	printf("  %zu 4KB data blocks per zone\n",
	       dev.zone_nr_blocks);

	switch (op) {

	case DMZ_OP_FORMAT:
		ret = dmz_format(&dev);
		break;

	case DMZ_OP_CHECK:
		ret = dmz_check(&dev);
		break;

	case DMZ_OP_REPAIR:
		ret = dmz_repair(&dev);
		break;

	case DMZ_OP_START:
		ret = dmz_start(&dev);
		break;

	default:

		fprintf(stderr, "Unknown operation\n");
		ret = 1;
		break;

	}

	free(dev.zones);
	dev.zones = NULL;
	dmz_close_dev(&dev.bdev[0]);

	return ret;
}

