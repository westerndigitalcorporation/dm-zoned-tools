/*
 * This file is part of dm-zoned tools.
 *
 * Copyright (C) 2020, SUSE Linux. All rights reserved.
 *
 * This software is distributed under the terms of the BSD 2-clause license,
 * "as is," without technical support, and WITHOUT ANY WARRANTY, without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. You should have received a copy of the BSD 2-clause license along
 * with dm-zoned tools.
 * If not, see <http://opensource.org/licenses/BSD-2-Clause>.
 *
 * Authors: Hannes Reinecke (hare@suse.com)
 */

#include "dmz.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <asm/byteorder.h>

#include <libdevmapper.h>

int dmz_init_dm(int log_level)
{
	struct dm_task *dmt;
	struct dm_versions *tgt, *last_tgt;
	int ret = -ENXIO;

	dm_log_with_errno_init(NULL);

	if (log_level > 1)
		dm_log_init_verbose(log_level - 1);

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		return -ENOMEM;

	dm_task_no_open_count(dmt);

	if (!dm_task_run(dmt)) {
		fprintf(stderr, "Failed to communicated with device-mapper\n");
		return -ENODEV;
	}

	tgt = dm_task_get_versions(dmt);
	do {
		last_tgt = tgt;
		if (!strncmp("zoned", tgt->name, 5)) {
			if (log_level)
				printf("Found dm-zoned version %d.%d.%d\n",
				       tgt->version[0], tgt->version[1],
				       tgt->version[2]);
			ret = 0;
			if (tgt->version[0] == 1) {
				ret = tgt->version[1];
				break;
			}
			fprintf(stderr,
				"Unsupported dm-zoned version %d.%d.%d\n",
				tgt->version[0], tgt->version[1],
				tgt->version[2]);
		}
		tgt = (void *) tgt + tgt->next;
	} while (last_tgt != tgt);

	dm_task_destroy(dmt);
	if (ret < 0)
		fprintf(stderr, "dm-zoned target not supported\n");
	return ret;
}
