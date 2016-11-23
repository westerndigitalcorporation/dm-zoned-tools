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

/*
 * Print usage.
 */
static void dmzadm_usage(void)
{
	printf("Usage: dmzadm <operation> <device path> [options]\n");
	printf("Operations:\n"
	       "  --help | -h	: General help message\n"
	       "  --format	: Format a block device metadata\n"
	       "  --check	: Check a block device metadata\n"
	       "  --repair	: Repair a block device metadata\n");

	printf("Common options(all operations):\n"
	       "  --verbose	: Verbose output\n"
	       "  --vverbose	: Very verbose output\n");

	printf("Format options:\n"
	       "  --seq <num>	: Number of sequential zones reserved\n"
	       "                  for reclaim. The minimum is 1 and the\n"
	       "                  default is %d\n",
	       DMZ_NR_RESERVED_SEQ);
}

/*
 * Main function.
 */
int main(int argc, char **argv)
{
	struct dmz_dev dev;
	int i, ret;
	int op;

	/* Initialize */
	memset(&dev, 0, sizeof(dev));
	dev.fd = -1;
	dev.nr_reserved_seq = DMZ_NR_RESERVED_SEQ;

	/* Parse operation */
	if (argc < 2 ||
	    strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "-h") == 0) {
		printf("dmzadm is for formatting, checking and repairing a zoned\n"
		       "block device for use with the dm-zoned device mapper.\n");
		dmzadm_usage();
		return 0;
	}

	if (strcmp(argv[1], "--format") == 0) {

		op = DMZ_OP_FORMAT;

	} else if (strcmp(argv[1], "--check") == 0) {

		op = DMZ_OP_CHECK;

	} else if (strcmp(argv[1], "--repair") == 0) {

		op = DMZ_OP_REPAIR;

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
	dev.path = argv[2];

	/* Parse arguments */
	for (i = 3; i < argc; i++) {

		if (strcmp(argv[i], "--verbose") == 0) {

			dev.flags |= DMZ_VERBOSE;

		} else if (strcmp(argv[i], "--vverbose") == 0) {

			dev.flags |= DMZ_VERBOSE | DMZ_VVERBOSE;

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

		} else if (argv[i][0] != '-') {

			break;

		} else {

			fprintf(stderr,
				"Unknown option \"%s\"\n",
				argv[i]);
			return 1;

		}

	}

	/* Open the device */
	if (dmz_open_dev(&dev) < 0)
		return 1;

	printf("%s: %llu 512-byte sectors (%llu GiB)\n",
	       dev.path,
	       dev.capacity,
	       (dev.capacity << 9) / (1024ULL * 1024ULL * 1024ULL));
	printf("  Host-%s device\n",
	       (dev.flags & DMZ_ZONED_HM) ? "managed" : "aware");
	printf("  %u zones of %zu 512-byte sectors (%zu MiB)\n",
	       dev.nr_zones,
	       dev.zone_nr_sectors,
	       (dev.zone_nr_sectors << 9) / (1024 * 1024));
	printf("  %zu 4KB chunk blocks per zone\n",
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

	default:

		fprintf(stderr, "Unknown operation\n");
		ret = 1;
		break;

	}

	dmz_close_dev(&dev);

	return ret;

}

