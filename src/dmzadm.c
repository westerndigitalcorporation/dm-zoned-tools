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

void dmz_dev_info(struct dmz_dev *dev)
{
	unsigned int nr_zones;

	printf("%s: %llu 512-byte sectors (%llu GiB)\n",
	       dev->path,
	       dev->capacity,
	       (dev->capacity << 9) / (1024ULL * 1024ULL * 1024ULL));
	printf("  Host-%s device\n",
	       (dev->dev_type == DMZ_TYPE_ZONED_HM) ? "managed" : "aware");
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
}

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

/*
 * Main function.
 */
int main(int argc, char **argv)
{
	struct dmz_dev_set set;
	int i, ret, log_level = 0, optarg;
	enum dmz_op op;

	/* Initialize */
	memset(&set, 0, sizeof(set));
	set.dev[0].fd = -1;
	set.dev[0].nr_reserved_seq = DMZ_NR_RESERVED_SEQ;

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
	optarg = 2;
	set.dev[0].path = argv[optarg];
	optarg++;

	/* Parse arguments */
	for (i = optarg; i < argc; i++) {

		if (strcmp(argv[i], "--verbose") == 0) {

			set.flags |= DMZ_VERBOSE;
			log_level = 1;

		} else if (strcmp(argv[i], "--vverbose") == 0) {

			set.flags |= DMZ_VERBOSE | DMZ_VVERBOSE;
			log_level = 2;

		} else if (strncmp(argv[i], "--seq=", 6) == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--seq option is valid only with the "
					"format operation\n");
				return 1;
			}

			set.dev[0].nr_reserved_seq = atoi(argv[i] + 6);
			if (set.dev[0].nr_reserved_seq <= 0) {
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
			memcpy(set.dmz_label, label, label_size);

		} else if (strcmp(argv[i], "--force") == 0) {

			if (op != DMZ_OP_FORMAT) {
				fprintf(stderr,
					"--force option is valid only with the "
					"format operation\n");
				return 1;
			}

			set.flags |= DMZ_OVERWRITE;

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

	set.if_version = ret;
	printf("Using interface version %d\n", set.if_version);

	if (op == DMZ_OP_STOP) {
		char holder[PATH_MAX];

		if (dmz_get_dev_holder(&set.dev[0], holder) < 0)
			return 1;
		if (!strlen(holder)) {
			fprintf(stderr, "%s: no dm-zoned device found\n",
				set.dev[0].name);
			return 1;
		}
		return dmz_stop(&set, holder);
	}

	/* Open the device */
	if (dmz_open_dev(&set.dev[0], op, set.flags) < 0)
		return 1;
	dmz_dev_info(&set.dev[0]);

	switch (op) {

	case DMZ_OP_FORMAT:
		ret = dmz_format(&set);
		break;

	case DMZ_OP_CHECK:
		ret = dmz_check(&set);
		break;

	case DMZ_OP_REPAIR:
		ret = dmz_repair(&set);
		break;

	case DMZ_OP_START:
		ret = dmz_start(&set);
		break;

	default:

		fprintf(stderr, "Unknown operation\n");
		ret = 1;
		break;

	}

	dmz_close_dev(&set.dev[0]);

	return ret;
}

