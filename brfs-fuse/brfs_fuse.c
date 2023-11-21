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

uint64_t
brfs_read_block_ptr(uint64_t block_idx) {
    if (lseek(fsfd, block_size_bytes * block_idx + block_data_size_bytes,
              SEEK_SET) < 0) {
        debug_log(1, "brfs_read_block_ptr: lseek: %s (reading block %d)\n",
                  strerror(errno), block_idx);
        return -1;
    }

    /* This is a ""text"" buffer for reading bytes, not the returning value */
    unsigned char ptr_buffer[pointer_size_bytes];
    if (read(fsfd, ptr_buffer, pointer_size_bytes) != pointer_size_bytes) {
        debug_log(1,
                  "brfs_read_block_ptr: read did not returned exactly "
                  "pointer_size_bytes (%d)",
                  pointer_size_bytes);
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

/** Return 1 if `next_blkid == curr_blkid + 1`, otherwise return next_blkid */
#define brfs_blockptr_resolve_diff(curr_blkid, next_blkid)                     \
    ((curr_blkid + 1 == next_blkid) ? 1 : next_blkid)

ssize_t
brfs_read(const brfs_dir_entry_64_t *entry, void *buf) {
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
    ssize_t written  = 0;
    ssize_t n_blocks = CALC_N_BLOCKS(n);

    for (size_t i = 0; i < n_blocks; i++) {
        bool   isLast = i == n_blocks - 1;
        size_t offset = (i * block_data_size_bytes);
        size_t nbytes = (isLast) ? n - offset : block_data_size_bytes;

        size_t sbffp = superblock->br_first_free;
        size_t nextp = brfs_advance_next_ptr();

        written += brfs_write_block(sbffp, buf + offset, nbytes);

        if (isLast) {
            brfs_write_block_ptr(superblock->br_first_free, 0);
        } else if (nextp == 0) {
            /* If it's a never written block, have to format it */
            brfs_write_block_ptr(sbffp, 1);
        }
    }

    return written;
}

ssize_t
brfs_write_file_offset(const brfs_dir_entry_64_t *file, const void *buf,
                       size_t n, size_t offset) {
    ssize_t written = 0;

    size_t nblock            = CALC_N_BLOCKS(offset) - 1;
    size_t blkdata_offsetted = nblock * block_data_size_bytes;
    size_t blockoffset       = offset - blkdata_offsetted;
    size_t block_data_available =
        blkdata_offsetted + block_data_size_bytes - offset;

    size_t block_idx = file->br_first_block;

    /* Skip offsetted blocks */
    for (size_t i = 0; i < nblock; i++) {
        size_t nextp = brfs_resolve_next_ptr(block_idx);
        if (!nextp) {
            /* Put a pointer in case that the offset is longer than the file */
            brfs_write_block_ptr(block_idx,
                                 brfs_blockptr_resolve_diff(
                                     block_idx, superblock->br_first_free));

            block_idx = superblock->br_first_free;
            brfs_advance_next_ptr();
            continue;
        } else if (i == nblock - 1) {
            /* If nextp != 0 and is the last iteration,
             * nextp requires to be zero (EOF) */
            brfs_write_block_ptr(nextp, 0);
        }

        block_idx = nextp;
    }

    size_t remaining_bytes = n;
    while (written < n) {
        written += brfs_write_block_offset(
            block_idx, buf + written,
            remaining_bytes > block_data_available ? block_data_available
                                                   : remaining_bytes,
            blockoffset);
        remaining_bytes -= written;

        /* Next block is full write */
        blockoffset          = 0;
        block_data_available = block_data_size_bytes;

        /* Resolve next block and continue */
        size_t current_block_idx = block_idx;
        block_idx                = brfs_resolve_next_ptr(block_idx);

        /* If there is no next_block, requires creating one */
        if (!block_idx && remaining_bytes > 0) {
            size_t next_pointer = brfs_blockptr_resolve_diff(
                current_block_idx, superblock->br_first_free);

            /* Write a pointer to the new block in the end of the file */
            brfs_write_block_ptr(current_block_idx, next_pointer);

            /* Write the remaining bytes */
            written += brfs_write(buf + written, remaining_bytes);
        }
    }

    return written;
}

/** Walk a file and return the block after blocks_offsetted, or the first block
 * with a EOF pointer */
size_t
brfs_file_get_nblock(const brfs_dir_entry_64_t *file_entry,
                     size_t                     blocks_offsetted) {

    size_t block_idx = file_entry->br_first_block;

    /* Travel to the last block */
    for (size_t i = 0; i < blocks_offsetted; i++) {
        size_t nextp = brfs_resolve_next_ptr(block_idx);
        if (!nextp)
            break;
        block_idx = nextp;
    }

    return block_idx;
}

/** Mark a file as deleted, and properly advances `superblock->br_first_free` */
void
brfs_file_delete(const brfs_dir_entry_64_t *file_entry) {
    size_t blocks_offsetted = CALC_N_BLOCKS(file_entry->br_file_size) - 1;

    size_t block_idx = brfs_file_get_nblock(file_entry, blocks_offsetted);

    brfs_write_block_ptr(block_idx, brfs_blockptr_resolve_diff(
                                        block_idx, superblock->br_first_free));
    superblock->br_first_free = file_entry->br_first_block;
}

/** Return 0 if success, or errno if failed */
int
brfs_file_truncate(brfs_dir_entry_64_t *file_entry, size_t length) {
    /* If no change, just return 0 */
    if (file_entry->br_file_size == length)
        return 0;

    if (length > file_entry->br_file_size) {
        /* Expand size with zero extended */
        ssize_t zero_buf_size = length - file_entry->br_file_size;
        void *  zero_buf      = calloc(zero_buf_size, 1);

        ssize_t written = brfs_write_file_offset(
            file_entry, zero_buf, zero_buf_size, file_entry->br_file_size);

        if (zero_buf_size != written) {
            debug_log(-1,
                      "brfs_file_truncate: I/O expected %ld, but read %ld "
                      "(brfs_write_file_offset)\n",
                      zero_buf_size, written);
            free(zero_buf);
            return -EIO;
        }

        free(zero_buf);
    } else {
        /* Free the trailing blocks */
        brfs_file_delete(file_entry);

        size_t blocks_offsetted = CALC_N_BLOCKS(length) - 1;
        size_t nblock = brfs_file_get_nblock(file_entry, blocks_offsetted);

        /* Make sure that not all the file is erased.
         * Ensure that only erasing the trailing blocks after length, because
         * brfs_file_delete will point superblock->br_first_free to the
         * begining of the file, but is fixed with the following line:
         */
        superblock->br_first_free = nblock + 1;

        /* Write EOF pointer at the new length */
        brfs_write_block_ptr(nblock, 0);
    }

    /* Finally, update file size */
    file_entry->br_file_size = length;

    return 0;
}

brfs_dir_entry_64_t *
brfs_find_in_dir(const char *filename, const brfs_dir_entry_64_t *dir,
                 size_t *foundon_offset) {
    size_t block_idx_dir = dir->br_first_block;

    void *dirbuf = malloc(dir->br_file_size);
    if (dir->br_file_size != brfs_read(dir, dirbuf)) {
        debug_log(1, "brfs_find_in_dir: Error reading file %s (EIO)\n",
                  &dir->br_file_name_firstc);
        if (dirbuf)
            free(dirbuf);
        return NULL;
    }

    void *dirbuf_max_addr = dirbuf + dir->br_file_size;

    brfs_dir_entry_64_t *e = (brfs_dir_entry_64_t *)dirbuf;
    while (((void *)e) + brfs_sizeof_dir_entry(e) <= dirbuf_max_addr) {
        if (strcmp(&e->br_file_name_firstc, filename) == 0) {
            /* FOUND */
            if (foundon_offset)
                *foundon_offset = ((void *)e) - dirbuf;

            brfs_dir_entry_64_t *r =
                memdup((void *)e, brfs_sizeof_dir_entry(e));

            free(dirbuf);
            return r;
        }

        /* Cast to (void*), because adding offset is in bytes, not sizeof */
        e = ((void *)e) + brfs_sizeof_dir_entry(e);
    }

    free(dirbuf);
    return NULL;
}

/*
 *
 */
int
brfs_walk_tree(const char *path, brfs_dir_entry_64_t **entry,
               brfs_dir_entry_64_t **parent_entry) {
    if (*path != '/') {
        debug_log(1, "brfs_walk_tree: error: Path not absolute\n");
        return -EIO;
    }

    brfs_dir_entry_64_t *prev_dir_entry =
        memdup(&superblock->br_root_ent, sizeof(brfs_dir_entry_64_t) + 1);
    /* +1, because `br_root_ent->br_file_name_firstc` is 1 char, but
     * the root entry name is "/", which i.e.: {'/','\0'} (see
     * brfs_mkfs.c)
     */

    /* Path is root, i.e.: `path == "/"` */
    if (strlen(path) == 1) {
        if (parent_entry)
            *parent_entry = NULL;

        if (entry)
            *entry = prev_dir_entry;

        return 0;
    }

    brfs_dir_entry_64_t *next_file = NULL;

    char *patht = strdup(path);
    char *tok   = strtok(patht, "/");
    while (tok) {
        /* If prev is not dir */
        if (!S_ISDIR(prev_dir_entry->br_attributes.br_mode)) {
            debug_log(1, "brfs_walk_tree: Token not a directory: %s\n", tok);
            if (prev_dir_entry != &superblock->br_root_ent)
                free(prev_dir_entry);
            free(patht);
            return -ENOTDIR;
        }

        /* Find tok in directory */
        next_file = brfs_find_in_dir(tok, prev_dir_entry, NULL);
        if (!next_file) {
            debug_log(1,
                      "brfs_walk_tree: file \"%s\" does not exist in dir "
                      "\"%s\" (%s) \n",
                      tok, &prev_dir_entry->br_file_name_firstc, path);
            free(prev_dir_entry);
            free(patht);
            return -ENOENT;
        }

        /* Propagate tok */
        tok = strtok(NULL, "/");
        if (!tok) /* Prevent overwriting prev_dir_entry */
            break;

        /* Operations to do, if there are more walk iterations,
         * i.e.: `tok != NULL` */

        free(prev_dir_entry);
        prev_dir_entry =
            memdup(next_file, brfs_sizeof_dir_entry(next_file)); // tofree

        /* free the previous data to avoid memory leak */
        free(next_file);
    }

    free(patht);

    if (parent_entry)
        *parent_entry = prev_dir_entry;
    else
        free(prev_dir_entry);

    /* Path propagated, next_file should be our file */
    if (entry)
        *entry = next_file;
    else
        free(next_file);

    return 0;
}

bool
brfs_file_exists(const char *path) {
    brfs_dir_entry_64_t *aux;
    return brfs_walk_tree(path, &aux, NULL) == 0;
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

/**
 * Write or modify (if already exists) an entry in a directory
 * @return 0 if success, errno otherwise
 */
int
brfs_write_entry(const brfs_dir_entry_64_t *dir,
                 const brfs_dir_entry_64_t *new_entry) {

    uint64_t                   foundon_offset = 0;
    const brfs_dir_entry_64_t *old_entry =
        brfs_find_in_dir(&new_entry->br_file_name_firstc, dir, &foundon_offset);

    if (!old_entry)
        foundon_offset = dir->br_file_size;

    size_t new_entry_size = brfs_sizeof_dir_entry(new_entry);

    ssize_t written = brfs_write_file_offset(dir, (void *)new_entry,
                                             new_entry_size, foundon_offset);
    if (new_entry_size != written) {
        debug_log(-1,
                  "brfs_write_entry: I/O expected %ld, but read %ld "
                  "(brfs_write_file_offset)\n",
                  new_entry_size, written);
        return -EIO;
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

/** Get extended attributes */
int
brfs_fuse_getxattr(const char *path, const char *name, char *value,
                   size_t size) {
    debug_log(1, "getxattr(\"%s\")\n", path);
    return 0;
}

/** Set extended attributes */
int
brfs_fuse_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags) {
    debug_log(1, "setxattr(\"%s\")\n", path);
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

    const char *_dirname = dirname(strdup(path));
    const char *nodname  = basename(strdup(path));

    int err = 0;

    /* Find directory */
    brfs_dir_entry_64_t *grandparent_dir;
    brfs_dir_entry_64_t *parent_dir;
    if ((err = brfs_walk_tree(_dirname, &parent_dir, &grandparent_dir)) < 0) {
        debug_log(1, "brfs_fuse_mknod: error brfs_walk_tree(\"%s\"): %s\n",
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

struct fuse_operations brfs_operations = {
    .getattr  = brfs_fuse_getattr,
    .getxattr = brfs_fuse_getxattr,
    .truncate = brfs_fuse_truncate,
    .utimens  = brfs_fuse_utimens,
    .chown    = brfs_fuse_chown,
    .readdir  = brfs_fuse_readdir,
    .read     = brfs_fuse_read,
    .write    = brfs_fuse_write,
    .mknod    = brfs_fuse_mknod,
    .mkdir    = brfs_fuse_mkdir,
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
