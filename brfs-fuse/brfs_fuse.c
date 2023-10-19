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
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>


#define FUSE_USE_VERSION    26
#define _FILE_OFFSET_BITS   64
#include <fuse.h>

#include "log.h"

#define BRFS_FUSE_DATA (*((struct brfs_fuse_state*)fuse_get_context()->private_data))




int
brfs_fuse_getattr(const char *path, struct stat *st) {
    debug_log(1, "getattr(\"%s\")\n", path);

    st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time(NULL); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time(NULL);

    if (strcmp(path, "/") == 0) {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else {
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}

    return 0;
}

int
brfs_fuse_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    debug_log(1, "readdir(\"%s\")\n", path);

    filler(buffer, ".", NULL, 0);
	filler(buffer, "..", NULL, 0);

    if (strcmp(path, "/" ) == 0) {
		filler(buffer, "thisfiledoesnotexist", NULL, 0);
	}

    return 0;
}

int
brfs_fuse_open(const char *path, struct fuse_file_info *) {
    debug_log(1, "open(\"%s\")\n", path);
    return 0;
}

int
brfs_fuse_read(const char *path, char *, size_t, off_t, struct fuse_file_info *) {
    debug_log(1, "read(\"%s\")\n", path);
    return 0;
}

struct fuse_operations brfs_operations = {
    .getattr = brfs_fuse_getattr,
    .readdir = brfs_fuse_readdir,
    .open = brfs_fuse_open,
    .read = brfs_fuse_read
};

struct brfs_fuse_state {
    int fsfd;
};

void
usage() {
    fprintf(stderr, "usage:  brfs-fuse [FUSE and mount options] device mount_point\n");
    abort();
}

int
main(int argc, char **argv) {
    struct brfs_fuse_state *brfs_fuse_data = malloc(sizeof(struct brfs_fuse_state));

    /* Check arguments */
    if ((argc < 3) || (argv[argc-1][0] == '-') || (argv[argc-2][0] == '-'))
	    usage();

    char *fsfile = argv[argc-2];
    char *mount_point = argv[argc-1];

    debug_log(1, "Mounting brfs volume at %s on %s\n", fsfile, mount_point);

    brfs_fuse_data->fsfd = open(fsfile, O_RDWR); /* revise: read-only option */
    if (brfs_fuse_data->fsfd < 0) {
        fprintf(stderr, "Error opening file or device file %s: %s\n", fsfile, strerror(errno));
    }

    int new_argc = 0;
    char *new_argv[100]; /* 100 max args */
    for (int i = 0; i < argc - 2; i++)
        new_argv[new_argc++] = argv[i];
    new_argv[new_argc++] = mount_point;
    new_argv[new_argc] = NULL;

    int fuse_ret = fuse_main(new_argc, new_argv, &brfs_operations, brfs_fuse_data);

    close(brfs_fuse_data->fsfd);

    return fuse_ret;
}
