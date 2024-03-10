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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FUSE_USE_VERSION  26
#define _FILE_OFFSET_BITS 64
#include <fuse.h>

#include "../common/brfs.h"
#include "../common/log.h"
#include "../core/brfs_core.h"

static const char BRFS_MAGIC_BYTES[4] = BRFS_MAGIC;

#define BRFS_FUSE_DATA                                                         \
    (*((struct brfs_fuse_state *)fuse_get_context()->private_data))

int
powi(int b, int e) {
    if (e == 0)
        return 1;

    int t = b;
    e--;
    while (e--)
        t *= b;
    return t;
}

/* ====================== FUSE OPERATIONS ======================*/

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.	 The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int
brfs_fuse_getattr(const char *path, struct stat *st) {
    debug_log(1, "getattr(\"%s\")\n", path);
    int err = 0;

    brfs_dir_entry_64_t *file_entry = NULL;
    if ((err = brfs_walk_tree(path, &file_entry, NULL)) < 0) {
        debug_log(1, "brfs_fuse_getattr: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    st->st_size        = file_entry->br_file_size;
    st->st_uid         = file_entry->br_attributes.br_uid;
    st->st_gid         = file_entry->br_attributes.br_gid;
    st->st_mode        = file_entry->br_attributes.br_mode;
    st->st_atim.tv_sec = file_entry->br_attributes.br_atime;
    st->st_mtim.tv_sec = file_entry->br_attributes.br_mtime;
    st->st_nlink       = 0;
    st->st_ino         = 0;

    free(file_entry);

    return 0;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
int
brfs_fuse_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi) {
    debug_log(1, "readdir(\"%s\")\n", path);

    int err = 0;

    /* Find directory */
    brfs_dir_entry_64_t *dir_entry = NULL;
    if ((err = brfs_walk_tree(path, &dir_entry, NULL)) < 0) {
        debug_log(1, "brfs_fuse_readdir: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    /* Read directory */
    brfs_dir_entry_64_t *dir_first = malloc(dir_entry->br_file_size);
    if (brfs_read(dir_entry, dir_first) < 0) {
        debug_log(1, "brfs_fuse_readdir: error brfs_read_dir on path: %s\n",
                  path);
        free(dir_entry);
        return -1;
    }

    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    const brfs_dir_entry_64_t *current_entry = dir_first;
    const brfs_dir_entry_64_t *max_dir =
        ((void *)dir_first) + dir_entry->br_file_size;

    while (current_entry < max_dir) {
        /* When a file amid the buffer has no name (not exist, but reserved
         * space), do not break the loop, just continue, because there are more
         * entries ahead */
        if (current_entry->br_file_name_firstc != '\0')
            filler(buffer, &current_entry->br_file_name_firstc, NULL, 0);

        /* Get next entry */
        current_entry =
            ((void *)current_entry) + brfs_sizeof_dir_entry(current_entry);
    }

    free(dir_first);
    return 0;
}

/**
 * @brief Change the size of a file
 * The truncate() and ftruncate() functions cause the regular file
 * named by path or referenced by fd to be truncated to a size of
 * precisely length bytes.
 *
 * If the file previously was larger than this size, the extra data
 * is lost.  If the file previously was shorter, it is extended, and
 * the extended part reads as null bytes ('\0').
 */
int
brfs_fuse_truncate(const char *path, off_t length) {
    int err = 0;

    brfs_dir_entry_64_t *file_parent;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &file_parent)) < 0) {
        debug_log(1, "brfs_fuse_truncate: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    /* If no change, don't reach brfs_write_entry */
    if (file_entry->br_file_size == length)
        return 0;

    err = brfs_file_truncate(file_entry, length);
    if (err != 0) {
        debug_log(-1, "brfs_fuse_truncate: brfs_file_truncate(%s): %s",
                  &file_entry->br_file_name_firstc, strerror(err));
        return err;
    }

    err = brfs_write_entry(file_parent, file_entry);

    return err;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * See the utimensat(2) man page for details.
 *
 * Introduced in version 2.6
 *
 * For both calls, the new file timestamps are specified in the
 * array times: times[0] specifies the new "last access time"
 * (atime); times[1] specifies the new "last modification time"
 * (mtime).  Each of the elements of times specifies a time as the
 * number of seconds and nanoseconds since the Epoch, 1970-01-01
 * 00:00:00 +0000 (UTC).  This information is conveyed in a
 * timespec(3) structure.
 */
int
brfs_fuse_utimens(const char *path, const struct timespec tv[2]) {

    int err = 0;

    brfs_dir_entry_64_t *file_parent;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &file_parent)) < 0) {
        debug_log(1, "brfs_fuse_utimens: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    file_entry->br_attributes.br_atime = (uint32_t)tv[0].tv_sec;
    file_entry->br_attributes.br_mtime = (uint32_t)tv[1].tv_sec;

    err = brfs_write_entry(file_parent, file_entry);

    return err;
}

/** Change the owner and group of a file */
int
brfs_fuse_chown(const char *path, uid_t uid, gid_t gid) {
    int err = 0;

    brfs_dir_entry_64_t *file_parent;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &file_parent)) < 0) {
        debug_log(1, "brfs_fuse_chown: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    file_entry->br_attributes.br_uid = uid;
    file_entry->br_attributes.br_gid = gid;

    err = brfs_write_entry(file_parent, file_entry);

    return err;
}

/** Change the permission bits of a file */
int
brfs_fuse_chmod(const char *path, mode_t mode) {
    int err = 0;

    brfs_dir_entry_64_t *file_parent;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &file_parent)) < 0) {
        debug_log(1, "brfs_fuse_chmod: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    file_entry->br_attributes.br_mode = mode;

    err = brfs_write_entry(file_parent, file_entry);

    return err;
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 */
int
brfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    debug_log(1, "open(\"%s\")\n", path);
    return 0;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
int
brfs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi) {
    debug_log(1, "read(\"%s\", %zu, %lld)\n", path, size, offset);

    int err = 0;

    brfs_dir_entry_64_t *parent_dir;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &parent_dir)) < 0) {
        debug_log(1, "brfs_fuse_read: error brfs_walk_tree(\"%s\"): %s\n", path,
                  strerror(err));
        return err;
    }

    return brfs_read(file_entry, buf);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
int
brfs_fuse_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi) {

    int err = 0;

    brfs_dir_entry_64_t *parent_dir;
    brfs_dir_entry_64_t *file_entry;
    if ((err = brfs_walk_tree(path, &file_entry, &parent_dir)) < 0) {
        debug_log(1, "brfs_fuse_write: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    ssize_t written = brfs_write_file_offset(file_entry, buf, size, offset);
    if (size != written) {
        debug_log(-1,
                  "brfs_fuse_write: I/O expected %ld, but read %ld "
                  "(brfs_write_file_offset)\n",
                  size, written);
        return -EIO;
    }

    file_entry->br_file_size = offset + size;

    err = brfs_write_entry(parent_dir, file_entry);

    return written;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
int
brfs_fuse_mknod(const char *path, mode_t mode, dev_t dev_t) {
    time_t creation_time = time(NULL);
    debug_log(1, "mknod(\"%s\", %o, %X)\n", path, mode, mode);

    const char *dirpath = getParentPath(path);
    const char *nodname = basename(path);

    int err = 0;

    /* Find directory */
    brfs_dir_entry_64_t *grandparent_dir;
    brfs_dir_entry_64_t *parent_dir;
    if ((err = brfs_walk_tree(dirpath, &parent_dir, &grandparent_dir)) < 0) {
        debug_log(1, "brfs_fuse_mknod: error brfs_walk_tree(\"%s\"): %s\n",
                  dirpath, strerror(err));
        return err;
    }

    /* Do not mknod if the entry already exists */
    if (brfs_file_exists(path)) {
        debug_log(1, "brfs_fuse_mknod: file %s already exists: %s\n", path,
                  strerror(EEXIST));
        return -EEXIST;
    }

    brfs_dir_entry_64_t *entry =
        brfs_new_entry(nodname, superblock->br_first_free, mode, creation_time);

    if ((err = brfs_write_entry(parent_dir, entry)) != 0) {
        debug_log(1, "brfs_fuse_mknod: could not write file %s (%s)\n", path,
                  strerror(err));
        return err;
    }

    /* Reserve one block for the file, and erase the previous ptr */
    uint64_t sbffp = superblock->br_first_free;
    brfs_advance_next_ptr();
    brfs_write_block_ptr(sbffp, 0);

    /* Update parent_dir size */
    if (strlen(&parent_dir->br_file_name_firstc) == 1) {
        /* Is Root */
        superblock->br_root_ent.br_file_size += brfs_sizeof_dir_entry(entry);
    } else {
        /* Increase parent size, and rewrite parent entry */
        parent_dir->br_file_size += brfs_sizeof_dir_entry(entry);
        brfs_write_entry(grandparent_dir, parent_dir);
    }

    return 0;
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
int
brfs_fuse_mkdir(const char *path, mode_t mode) {
    return brfs_fuse_mknod(path, mode | S_IFDIR,
                           0 /* TODO: figure out which dev_t to use */);
}

/** Remove a file */
int
brfs_fuse_unlink(const char *path) {
    int err = 0;

    brfs_dir_entry_64_t *grandparent_dir = NULL;
    brfs_dir_entry_64_t *parent_dir      = NULL;

    char *filename    = basename(path);
    char *parent_path = getParentPath(path);

    /* Get parent and grandparent by path */
    if ((err = brfs_walk_tree(parent_path, &parent_dir, &grandparent_dir)) <
        0) {
        debug_log(1, "brfs_fuse_unlink: error brfs_walk_tree(\"%s\"): %s\n",
                  parent_path, strerror(err));

        free(filename);
        free(parent_path);
        if (parent_dir)
            free(parent_dir);
        if (grandparent_dir)
            free(grandparent_dir);

        return err;
    }

    free(parent_path);

    /* Get file entry before wiping it from it's parent */
    brfs_dir_entry_64_t *file_entry =
        brfs_find_in_dir(filename, parent_dir, NULL);

    /* Unlink */
    if ((err = brfs_unlink_entry(filename, parent_dir, grandparent_dir)) < 0) {
        debug_log(1, "brfs_fuse_unlink: error brfs_unlink_entry(\"%s\"): %s\n",
                  path, strerror(err));

        free(filename);
        if (file_entry)
            free(file_entry);
        if (parent_dir)
            free(parent_dir);
        if (grandparent_dir)
            free(grandparent_dir);

        return err;
    }

    if (grandparent_dir)
        free(grandparent_dir);

    /* Mark file as removed and setup sbff */
    brfs_file_delete(file_entry);

    /* Clean up */
    free(filename);
    free(file_entry);
    if (parent_dir)
        free(parent_dir);

    return 0;
}

struct fuse_operations brfs_operations = {
    .getattr  = brfs_fuse_getattr,
    .truncate = brfs_fuse_truncate,
    .utimens  = brfs_fuse_utimens,
    .chown    = brfs_fuse_chown,
    .chmod    = brfs_fuse_chmod,
    .readdir  = brfs_fuse_readdir,
    .read     = brfs_fuse_read,
    .write    = brfs_fuse_write,
    .mknod    = brfs_fuse_mknod,
    .mkdir    = brfs_fuse_mkdir,
    .unlink   = brfs_fuse_unlink,
    .rmdir    = brfs_fuse_unlink,
};

struct brfs_fuse_state {};

void
usage() {
    fprintf(stderr,
            "usage:  brfs-fuse [FUSE and mount options] device mount_point\n");
    abort();
}

int
main(int argc, char **argv) {
    struct brfs_fuse_state *brfs_fuse_data =
        malloc(sizeof(struct brfs_fuse_state));

    /* Check arguments */
    if ((argc < 3) || (argv[argc - 1][0] == '-') || (argv[argc - 2][0] == '-'))
        usage();

    char *fsfile      = argv[argc - 2];
    char *mount_point = argv[argc - 1];

    debug_log(1, "Mounting brfs volume at %s on %s\n", fsfile, mount_point);

    fsfd = open(fsfile, O_RDWR); /* revise: read-only option */
    if (fsfd < 0) {
        fprintf(stderr, "Error opening file or device file %s: %s\n", fsfile,
                strerror(errno));
    }

    struct stat st;
    if (fstat(fsfd, &st) < 0) {
        aborterr(-1, "Error stating file or device %s: %s\n", fsfile,
                 strerror(errno));
    }

    void *mapped = NULL;
    if ((mapped = mmap(NULL, BRFS_SUPERBLOCK_MAX_SIZE, PROT_WRITE, MAP_SHARED,
                       fsfd, 0)) == MAP_FAILED) {
        close(fsfd);
        aborterr(-1, "Error mmapping file or device %s: %s\n", fsfile,
                 strerror(errno));
    }

    superblock            = (brfs_superblock_64_t *)mapped;
    block_size_bytes      = powi(2, 9 + superblock->br_block_size);
    pointer_size_bytes    = superblock->br_ptr_size;
    block_data_size_bytes = block_size_bytes - pointer_size_bytes;

    /* Check filesystem */
    if (memcmp(superblock->br_magic, BRFS_MAGIC_BYTES,
               sizeof(BRFS_MAGIC_BYTES)) != 0) {
        fprintf(stderr, "Error: %s is not a brfs volume.\n", fsfile);
        exit(1);
    }
    if (superblock->br_ptr_size != 2 && superblock->br_ptr_size != 4 &&
        superblock->br_ptr_size != 8) {
        fprintf(stderr,
                "Error: invalid volume pointer size (bytes) %d,\nthe only "
                "valid values are:  2 (16 bits), 4 (32 bits), 8 (64 bits).\n",
                superblock->br_ptr_size);
        exit(1);
    }

    /* Cool */
    printf("Block size: %ld\nPointer size: %d\nFS size: %ld\nFree blocks: "
           "%ld\nFirst free block: %ld\n",
           block_size_bytes, superblock->br_ptr_size, superblock->br_fs_size,
           superblock->br_free_blocks, superblock->br_first_free);

    /* FUSE main */

    int   new_argc = 0;
    char *new_argv[100]; /* 100 max args */
    for (int i = 0; i < argc - 2; i++)
        new_argv[new_argc++] = argv[i];
    new_argv[new_argc++] = mount_point;
    new_argv[new_argc]   = NULL;

    int fuse_ret =
        fuse_main(new_argc, new_argv, &brfs_operations, brfs_fuse_data);

    munmap(mapped, BRFS_SUPERBLOCK_MAX_SIZE);
    close(fsfd);

    return fuse_ret;
}
