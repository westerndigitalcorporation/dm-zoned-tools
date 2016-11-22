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
	printf("Usage: dmzadm [options] [operation] device\n");
	printf("Options:\n"
	       "  --help	-h  : General help message\n"
	       "  --verbose	-v  : Verbose output\n"
	       "  --vverbose	-vv : Very verbose output\n");
	printf("Operations:\n"
	       "  --format	-f  : Format a block device metadata\n"
	       "  --check	-c  : Check a block device metadata\n");
}

/*
 * Main function.
 */
int main(int argc, char **argv)
{
	struct dmz_dev dev;
	int i, ret;
	int op = 0;

	/* Initialize */
	memset(&dev, 0, sizeof(dev));
	dev.fd = -1;

	/* Parse arguments */
	for (i = 1; i < argc; i++) {

		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			printf("dmzadm is for formatting or checking a zoned\n"
			       "block device for use with the dm-zoned device mapper.\n");
			dmzadm_usage();
			return 0;
		}

		if (strcmp(argv[i], "--verbose") == 0 ||
		    strcmp(argv[i], "-v") == 0) {

			dev.flags |= DMZ_VERBOSE;

		} else if (strcmp(argv[i], "--vverbose") == 0 ||
			   strcmp(argv[i], "-vv") == 0) {

			dev.flags |= DMZ_VERBOSE | DMZ_VVERBOSE;

		} else if (strcmp(argv[i], "--format") == 0 ||
			   strcmp(argv[i], "-f") == 0) {

			if (op) {
				fprintf(stderr,
					"Multiple operations specified\n");
				return 1;
			}
			op = DMZ_FORMAT;

		} else if (strcmp(argv[i], "--check") == 0 ||
			   strcmp(argv[i], "-c") == 0) {

			if (op) {
				fprintf(stderr,
					"Multiple operations specified\n");
				return 1;
			}
			op = DMZ_CHECK;

		} else if (argv[i][0] != '-') {

			break;

		} else {

			fprintf(stderr,
				"Unknown option \"%s\"\n",
				argv[i]);
			return 1;

		}

	}

	if (!op) {
		fprintf(stderr, "No operation specified\n");
		return 1;
	}

	if (i != argc - 1) {
		fprintf(stderr, "Invalid command line\n");
		dmzadm_usage();
		return 1;
	}

	/* Open the device */
	dev.path = argv[i];
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

	ret = 0;

	switch (op) {

	case DMZ_FORMAT:
		ret = dmz_format(&dev);
		break;

	case DMZ_CHECK:
		ret = dmz_check(&dev);
		break;

	case DMZ_REPAIR:
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

