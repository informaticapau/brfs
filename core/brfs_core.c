#include "brfs_core.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../common/log.h"

int                   fsfd               = 0;
brfs_superblock_64_t *superblock         = NULL;
size_t                block_size_bytes   = 0;
size_t                pointer_size_bytes = 0;

/** block_data_size_bytes = block_size_bytes - pointer_size_bytes; */
size_t block_data_size_bytes = 0;


void *
memdup(const void *mem, size_t size) {
    void *out = malloc(size);

    if (out != NULL)
        memcpy(out, mem, size);

    return out;
}

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
brfs_read_block_offset(uint64_t block_idx, void *buf, size_t n, size_t offset) {
    if (lseek(fsfd, block_size_bytes * block_idx + offset, SEEK_SET) < 0) {
        debug_log(1, "brfs_read_block_offset: lseek: %s\n", strerror(errno));
        return -1;
    }

    return read(fsfd, buf, n);
}

ssize_t
brfs_read_block(uint64_t block_idx, void *buf, size_t n) {
    return brfs_read_block_offset(block_idx, buf, n, 0);
}

ssize_t
brfs_write_block_offset(uint64_t block_idx, const void *buf, size_t n,
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
brfs_write_block(uint64_t block_idx, const void *buf, size_t n) {
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
brfs_write_block_ptr(uint64_t block_idx, size_t next_pointer) {
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
uint64_t
brfs_advance_next_ptr() {
    uint64_t nextp = brfs_read_block_ptr(superblock->br_first_free);

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
        int err = brfs_read_block(block_idx, buf + readed,
                                  (i == n_blocks - 1)
                                      ? entry->br_file_size -
                                            (i * block_data_size_bytes)
                                      : block_data_size_bytes);

        /* Check errors */
        if (err == -1)
            return err;

        /* Continue to next block */
        readed += err;
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
        uint64_t nextp = brfs_resolve_next_ptr(block_idx);
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
        uint64_t current_block_idx = block_idx;
        block_idx                  = brfs_resolve_next_ptr(block_idx);

        /* If there is no next_block, requires creating one */
        if (!block_idx && remaining_bytes > 0) {
            uint64_t next_pointer = brfs_blockptr_resolve_diff(
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
uint64_t
brfs_file_get_nblock(const brfs_dir_entry_64_t *file_entry,
                     size_t                     blocks_offsetted) {

    uint64_t block_idx = file_entry->br_first_block;

    /* Travel to the last block */
    for (size_t i = 0; i < blocks_offsetted; i++) {
        uint64_t nextp = brfs_resolve_next_ptr(block_idx);
        if (!nextp)
            break;
        block_idx = nextp;
    }

    return block_idx;
}

/** Mark a file as deleted, and properly advances `superblock->br_first_free` */
void
brfs_file_delete(const brfs_dir_entry_64_t *file_entry) {
    if (!file_entry)
        return;

    size_t blocks_offsetted = CALC_N_BLOCKS(file_entry->br_file_size) - 1;

    uint64_t block_idx = brfs_file_get_nblock(file_entry, blocks_offsetted);

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

        uint64_t blocks_offsetted = CALC_N_BLOCKS(length) - 1;
        uint64_t nblock = brfs_file_get_nblock(file_entry, blocks_offsetted);

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
    uint64_t block_idx_dir = dir->br_first_block;

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

char *
getParentPath(const char *path) {
    char *tok = (char *)path + strlen(path);
    while (*tok != '/' && tok > path)
        tok--;

    /* If parent is root, return "/" */
    if (tok == path)
        tok++;

    size_t ppath_size = tok - path;

    char *ppath       = strndup(path, ppath_size + 1);
    ppath[ppath_size] = '\0';

    return ppath;
}

char *
basename(const char *path) {
    char *tok = (char *)path + strlen(path);
    while (*tok != '/' && tok > path)
        tok--;
    tok++;

    return strdup(tok);
}

char *
dirname(const char *path) {
    char *tok = (char *)path + strlen(path);

    /* Skip basename */
    while (*tok != '/' && tok > path)
        tok--;

    const char *tokl = tok;
    tok--;

    while (*tok != '/' && tok > path)
        tok--;
    tok++;

    ssize_t dirname_size = tokl - tok;

    char *dirname         = strndup(tok, dirname_size + 1);
    dirname[dirname_size] = '\0';

    return dirname;
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

int
brfs_unlink_entry(const char *filename, brfs_dir_entry_64_t *dir,
                  brfs_dir_entry_64_t *parent_dir) {
    int err = 0;

    /* Read dir as file */
    void *dirbuf = malloc(dir->br_file_size);

    if (dir->br_file_size != brfs_read(dir, dirbuf)) {
        debug_log(1, "brfs_unlink_entry: (I/O) brfs_read");
        free(dirbuf);
        return -EIO;
    }

    size_t offset = 0;

    /* Find entry by filename */
    brfs_dir_entry_64_t *file_entry = brfs_find_in_dir(filename, dir, &offset);
    if (!file_entry) {
        free(dirbuf);
        return -ENOENT;
    }

    ssize_t file_entry_size = brfs_sizeof_dir_entry(file_entry);
    free(file_entry);

    /* Trim entry */
    memcpy(dirbuf + offset, dirbuf + offset + file_entry_size,
           dir->br_file_size - offset - file_entry_size);

    /* Resize dir */
    dir->br_file_size -= file_entry_size;

    /* If is root */
    if (dir->br_first_block == 1)
        superblock->br_root_ent.br_file_size = dir->br_file_size;

    /* Rewrite dir data */
    if (dir->br_file_size !=
        brfs_write_file_offset(dir, dirbuf, dir->br_file_size, 0)) {
        debug_log(1, "brfs_unlink_entry: (I/O) brfs_write_file_offset");
        free(dirbuf);
        return -EIO;
    }

    /* Rewrite dir entry to parent */
    if (parent_dir != NULL && (err = brfs_write_entry(parent_dir, dir)) != 0) {
        debug_log(1, "brfs_unlink_entry: brfs_write_entry: %s", strerror(err));
        free(dirbuf);
        return err;
    }

    /* Clean up */
    free(dirbuf);

    return 0;
}
