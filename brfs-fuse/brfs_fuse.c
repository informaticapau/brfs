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

#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define FUSE_USE_VERSION  26
#define _FILE_OFFSET_BITS 64
#include <fuse.h>

#include "../common/brfs.h"
#include "../common/log.h"

#define BRFS_FUSE_DATA                                                         \
    (*((struct brfs_fuse_state *)fuse_get_context()->private_data))

void *
memdup(const void *mem, size_t size) {
    void *out = malloc(size);

    if (out != NULL)
        memcpy(out, mem, size);

    return out;
}

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

int                   fsfd               = 0;
brfs_superblock_64_t *superblock         = NULL;
size_t                block_size_bytes   = 0;
size_t                pointer_size_bytes = 0;

/** block_data_size_bytes = block_size_bytes - pointer_size_bytes; */
size_t block_data_size_bytes = 0;

size_t
brfs_sizeof_dir_entry(const brfs_dir_entry_64_t *dir_entry) {
    /* Do not add 1, because brfs_dir_entry_64_t already has a char in
     * `br_file_name_firstc` */
    return sizeof(brfs_dir_entry_64_t) +
           strlen(&dir_entry->br_file_name_firstc);
}

/** Return how many blocks will it take to fill with n bytes of data */
#define CALC_N_BLOCKS(n) ((n / (block_data_size_bytes + 1)) + 1)

ssize_t
brfs_read_block_offset(size_t block_idx, void *buf, size_t n, size_t offset) {
    if (lseek(fsfd, block_size_bytes * block_idx + offset, SEEK_SET) < 0) {
        debug_log(1, "brfs_read_block_offset: lseek: %s\n", strerror(errno));
        return -1;
    }

    return read(fsfd, buf, n);
}

ssize_t
brfs_read_block(size_t block_idx, void *buf, size_t n) {
    return brfs_read_block_offset(block_idx, buf, n, 0);
}

ssize_t
brfs_write_block_offset(size_t block_idx, const void *buf, size_t n,
                        size_t offset) {
    if (block_idx == 0)
        return -1; /* Cannot write to protected Superblock */

    if (lseek(fsfd, block_size_bytes * block_idx + offset, SEEK_SET) < 0) {
        debug_log(1, "brfs_write_block_offset: lseek: %s\n", strerror(errno));
        return -1;
    }

    return write(fsfd, buf, n);
}

ssize_t
brfs_write_block(size_t block_idx, const void *buf, size_t n) {
    return brfs_write_block_offset(block_idx, buf, n, 0);
}

int
brfs_zero_block(size_t block_idx) {
    if (block_idx == 0)
        return -1; /* Cannot write to protected Superblock */

    uint8_t *zeros = calloc(block_size_bytes, 1);
    if (!zeros) {
        debug_log(1, "brfs_zero_block: %s\n", strerror(errno));
        return -1;
    }

    if (lseek(fsfd, block_size_bytes * block_idx, SEEK_SET) < 0) {
        debug_log(1, "brfs_zero_block: lseek: %s\n", strerror(errno));
        free(zeros);
        return -1;
    }

    if (block_size_bytes != write(fsfd, zeros, block_size_bytes)) {
        debug_log(1,
                  "brfs_zero_block: read did not returned exactly "
                  "block_size_bytes (%d)",
                  block_size_bytes);
        free(zeros);
        return -1;
    }

    free(zeros);

    return 0;
}

uint64_t
brfs_read_block_ptr(uint64_t block_idx) {
    /* This is a ""text"" buffer for reading bytes, not the returning value */
    unsigned char ptr_buffer[pointer_size_bytes];

    if (lseek(fsfd, block_size_bytes * block_idx + block_data_size_bytes,
              SEEK_SET) < 0) {
        debug_log(1, "brfs_read_block_ptr: lseek: %s\n", strerror(errno));
        free(ptr_buffer);
        return -1;
    }

    if (read(fsfd, ptr_buffer, pointer_size_bytes) != pointer_size_bytes) {
        debug_log(1,
                  "brfs_read_block_ptr: read did not returned exactly "
                  "pointer_size_bytes (%d)",
                  pointer_size_bytes);
        free(ptr_buffer);
        return -1;
    }

    /* Convert ptr_buffer to number */
    uint64_t r = 0;
    for (uint8_t i = 0; i < pointer_size_bytes; i++)
        r |= (*(ptr_buffer + i)) << 8 * i;

    return r;
}

void
brfs_write_block_ptr(size_t block_idx, size_t next_pointer) {
    if (block_idx == 0)
        return; /* Cannot write to protected Superblock */

    if (lseek(fsfd, block_size_bytes * block_idx + block_data_size_bytes,
              SEEK_SET) < 0) {
        debug_log(1, "brfs_write_block_and_pointer: lseek: %s\n",
                  strerror(errno));
        return;
    }

    unsigned char p[pointer_size_bytes];
    for (uint8_t i = 0; i < pointer_size_bytes; i++)
        p[i] = (unsigned char)(next_pointer >> 8 * i);

    write(fsfd, p, sizeof(p));
}

uint64_t
brfs_resolve_next_ptr(uint64_t block_idx) {
    uint64_t next_ptr = brfs_read_block_ptr(block_idx);
    return (next_ptr == 1) ? block_idx + 1 : next_ptr;
}

/**
 * @brief properly advances `superblock->br_first_free`
 * @return size_t `brfs_read_block_ptr(superblock->br_first_free)`
 */
size_t
brfs_advance_next_ptr() {
    size_t nextp = brfs_read_block_ptr(superblock->br_first_free);

    switch (nextp) {
        /* Means that the next block is writable
            1: next sector is available, and handles a valid next (free) pointer
            0: next sector is available, and requires format as 0 */
    case 0:
        brfs_write_block_ptr(1 + superblock->br_first_free, 0);
    case 1:
        superblock->br_first_free++;
        break;
    default:
        superblock->br_first_free = nextp;
        break;
    }

    return nextp;
}

ssize_t
brfs_read(brfs_dir_entry_64_t *entry, void *buf) {
    size_t   readed    = 0;
    uint64_t block_idx = entry->br_first_block;

    /* Number of blocks to read */
    size_t n_blocks = CALC_N_BLOCKS(entry->br_file_size);

    for (size_t i = 0; i < n_blocks; i++) {
        readed += brfs_read_block(block_idx, buf + readed,
                                  (i == n_blocks - 1)
                                      ? entry->br_file_size -
                                            (i * block_data_size_bytes)
                                      : block_data_size_bytes);

        block_idx = brfs_resolve_next_ptr(block_idx);
    }

    return readed;
}

ssize_t
brfs_write(const void *buf, size_t n) {
    /* Number of blocks to write */
    ssize_t n_blocks = CALC_N_BLOCKS(n);

    for (size_t i = 0; i < n_blocks; i++) {
        bool   isLast = i == n_blocks - 1;
        size_t offset = (i * block_data_size_bytes);
        size_t nbytes = (isLast) ? n - offset : block_data_size_bytes;

        size_t sbffp = superblock->br_first_free;
        size_t nextp = brfs_advance_next_ptr();

        brfs_write_block(sbffp, buf + offset, nbytes);

        if (isLast) {
            brfs_write_block_ptr(superblock->br_first_free, 0);
        } else if (nextp == 0) {
            /* If it's a never written block, have to format it */
            brfs_write_block_ptr(sbffp, 1);
        }
    }

    return n_blocks;
}

brfs_dir_entry_64_t *
brfs_find_in_dir(const char *filename, brfs_dir_entry_64_t *dir,
                 const char *dirbuf, uint64_t *foundon_block_idx) {
    size_t block_idx_dir = dir->br_first_block;

    while (block_idx_dir != 0) {
        /* Read the block */
        if (brfs_read_block(block_idx_dir, (void *)dirbuf, block_size_bytes) !=
            block_size_bytes) {
            debug_log(-1, "brfs_find_in_dir: Error reading block_idx %d\n",
                      block_idx_dir);
            return NULL;
        }

        brfs_dir_entry_64_t *e = (brfs_dir_entry_64_t *)dirbuf;

        while ((char *)e < dirbuf + block_data_size_bytes) {
            if (strcmp(&e->br_file_name_firstc, filename) == 0) {
                /* FOUND */
                if (foundon_block_idx)
                    *foundon_block_idx = block_idx_dir;
                return e;
            }

            /* Cast to (void*), because adding offset is in bytes, not sizeof */
            e = ((void *)e) + brfs_sizeof_dir_entry(e);
        }

        /* Get next pointer */
        block_idx_dir = brfs_resolve_next_ptr(block_idx_dir);
    }

    return NULL;
}

int
brfs_walk_tree(const char *path, brfs_dir_entry_64_t **entry) {
    if (*path != '/') {
        debug_log(1, "brfs_walk_tree: error: Path not absolute\n");
        return -EIO;
    }
    if (strlen(path) == 1) {
        if (entry)
            *entry = memdup(&superblock->br_root_ent,
                            sizeof(brfs_dir_entry_64_t) + 1);
        /* +1, because `br_root_ent->br_file_name_firstc` is 1 char, but
         * the root entry name is "/", which i.e.: {'/','\0'} (see brfs_mkfs.c)
         */
        return 0;
    }

    char dirbuf[block_size_bytes];

    brfs_dir_entry_64_t *prev_dir_entry = &superblock->br_root_ent;
    brfs_dir_entry_64_t *next_file      = NULL;

    char *patht = strdup(path);
    char *tok   = strtok(patht, "/");
    while (tok) {
        /* If prev is not dir */
        if (!S_ISDIR(prev_dir_entry->br_attributes.br_mode)) {
            debug_log(1, "brfs_walk_tree: Token not a directory: %s\n", tok);
            if (prev_dir_entry != &superblock->br_root_ent)
                free(prev_dir_entry);
            return -ENOTDIR;
        }

        /* Find tok in directory */
        next_file = brfs_find_in_dir(tok, prev_dir_entry, dirbuf, NULL);
        if (!next_file) {
            debug_log(1, "brfs_walk_tree: file does not exist: %s\n", path);
            if (prev_dir_entry != &superblock->br_root_ent)
                free(prev_dir_entry);

            return -ENOENT;
        }

        /* Propagate tok */
        prev_dir_entry = memdup(next_file, brfs_sizeof_dir_entry(next_file));
        tok            = strtok(NULL, "/");
    }

    if (prev_dir_entry != &superblock->br_root_ent)
        free(prev_dir_entry);

    /* Path propagated, next_file should be our file */
    if (entry)
        *entry = next_file;

    return 0;
}

bool
brfs_file_exists(const char *path) {
    brfs_dir_entry_64_t *aux;
    return brfs_walk_tree(path, &aux) == 0;
}

brfs_dir_entry_64_t *
brfs_new_entry(const char *nodname, uint64_t first_block, uint16_t mode,
               time_t creation_time) {

    size_t entry_size = sizeof(brfs_dir_entry_64_t) + strlen(nodname);

    brfs_dir_entry_64_t *entry     = (brfs_dir_entry_64_t *)malloc(entry_size);
    entry->br_file_size            = 0;
    entry->br_file_name_firstc     = 0;
    entry->br_first_block          = first_block;
    entry->br_attributes.br_crtime = creation_time;
    entry->br_attributes.br_atime  = creation_time;
    entry->br_attributes.br_mtime  = creation_time;
    entry->br_attributes.br_uid    = getuid(); /* fix later */
    entry->br_attributes.br_gid    = getgid();
    entry->br_attributes.br_mode   = mode;
    strcpy(&entry->br_file_name_firstc, nodname);

    return entry;
}

int
brfs_write_entry(brfs_dir_entry_64_t *      dir,
                 const brfs_dir_entry_64_t *new_entry) {
    size_t block_idx_dir  = dir->br_first_block;
    size_t new_entry_size = brfs_sizeof_dir_entry(new_entry);

    char     dirbuf[block_size_bytes];
    uint64_t block_idx_new = 0;

    /* Search for an available space (filename == "") */
    brfs_dir_entry_64_t *place =
        brfs_find_in_dir("", dir, dirbuf, &block_idx_new);

    if (!place) {
        /* Never found a fit. Write to a new block
           TODO: Append new block */
        return -ENOSPC;
    } else {
        /* Write the new dirbuf to corresponding block */
        memcpy(place, new_entry, new_entry_size);
        if (sizeof(dirbuf) !=
            brfs_write_block(block_idx_new, dirbuf, sizeof(dirbuf))) {
            return -EIO;
        }
    }

    return 0;
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
    if ((err = brfs_walk_tree(path, &file_entry)) < 0) {
        debug_log(1, "brfs_fuse_getattr: error brfs_walk_tree(\"%s\"): %s\n",
                  path, strerror(err));
        return err;
    }

    st->st_size  = file_entry->br_file_size;
    st->st_uid   = file_entry->br_attributes.br_uid;
    st->st_gid   = file_entry->br_attributes.br_gid;
    st->st_mode  = file_entry->br_attributes.br_mode;
    st->st_atime = file_entry->br_attributes.br_atime;
    st->st_mtime = file_entry->br_attributes.br_mtime;
    st->st_nlink = 0;
    st->st_ino   = 0;

    /* The following line keeps throwing me a double free error, uncomment it
     * under your own risk.
     * TODO: Investigate */
    // free(file_entry);

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
    if ((err = brfs_walk_tree(path, &dir_entry)) < 0) {
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
            (void *)current_entry + brfs_sizeof_dir_entry(current_entry);
    }

    free(dir_first);
    return 0;
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
    debug_log(1, "read(\"%s\")\n", path);
    return 0;
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

    const char *_dirname = dirname(strdup(path));
    const char *nodname  = basename(strdup(path));

    int err = 0;

    /* Find directory */
    brfs_dir_entry_64_t *parent_dir;
    if ((err = brfs_walk_tree(_dirname, &parent_dir)) < 0) {
        debug_log(1, "brfs_fuse_mknod: error brfs_walk_tree(\"%s\"): %s\n ",
                  _dirname, strerror(err));
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

    brfs_advance_next_ptr();

    /* Update parent_dir size */
    if (strlen(&parent_dir->br_file_name_firstc) == 1) {
        /* Is Root */
        superblock->br_root_ent.br_file_size += brfs_sizeof_dir_entry(entry);
    } else {
        /* TODO: BR1 */
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
    brfs_zero_block(superblock->br_first_free);

    return brfs_fuse_mknod(path, mode | S_IFDIR,
                           0 /* TODO: figure out which dev_t to use */);
}

struct fuse_operations brfs_operations = {
    .getattr = brfs_fuse_getattr,
    .readdir = brfs_fuse_readdir,
    .open    = brfs_fuse_open,
    .read    = brfs_fuse_read,
    .mknod   = brfs_fuse_mknod,
    .mkdir   = brfs_fuse_mkdir,
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
