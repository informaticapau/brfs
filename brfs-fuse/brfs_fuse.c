/*
    BRFS
    Copyright (C) 2023 Ángel Ruiz Fernandez <arf20>
    Copyright (C) 2023 Bruno Castro García <bruneo32>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    brfs_fuse.c: Filesystem in Userspace implementation for BRFS
*/

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#define FUSE_USE_VERSION    26
#define _FILE_OFFSET_BITS   64
#include <fuse.h>

#include "log.h"

#define BRFS_FUSE_DATA ((struct brfs_fuse_state*)fuse_get_context()->private_data)




int
brfs_fuse_getattr(const char *path, struct stat *) {
    debug_log(1, "brfs_fuse_getattr(path=%s,)\n", path);
    return 0;
}

int
brfs_fuse_open(const char *path, struct fuse_file_info *) {
    debug_log(1, "brfs_fuse_open\n");
    return 0;
}

int
brfs_fuse_read(const char *path, char *, size_t, off_t, struct fuse_file_info *) {
    debug_log(1, "brfs_fuse_read\n");
    return 0;
}

struct fuse_operations brfs_operations = {
    .getattr = brfs_fuse_getattr,
    .open = brfs_fuse_open,
    .read = brfs_fuse_read
};

struct brfs_fuse_state {
    char *rootdir;
};

void
usage() {
    fprintf(stderr, "usage:  brfs-fuse [FUSE and mount options] mount_point\n");
    abort();
}

int
main(int argc, char **argv) {
    struct brfs_fuse_state *brfs_fuse_data = malloc(sizeof(struct brfs_fuse_state));
    
    /* Disallow root to mount FUSE filesystems */
    if ((getuid() == 0) || (geteuid() == 0)) {
        fprintf(stderr, "Running BRFS as root opens unnacceptable security holes\n");
        return 1;
    }

    /* Check arguments */
    if ((argc < 2) || (argv[argc-1][0] == '-'))
	    usage();

    debug_log(1, "Mounting brfs on %s\n", argv[argc - 1]);

    return fuse_main(argc, argv, &brfs_operations, brfs_fuse_data);
}
