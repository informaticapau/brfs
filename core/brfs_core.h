#ifndef _BRFS_CORE_H
#define _BRFS_CORE_H

#include <stdio.h>
#include <time.h>
#include <stdbool.h>

#include "../common/brfs.h"

extern int                   fsfd;
extern brfs_superblock_64_t *superblock;
extern size_t                block_size_bytes;
extern size_t                pointer_size_bytes;

/** block_data_size_bytes = block_size_bytes - pointer_size_bytes; */
extern size_t block_data_size_bytes;

void *memdup(const void *mem, size_t size);

size_t brfs_sizeof_dir_entry(const brfs_dir_entry_64_t *dir_entry);

/** Return how many blocks will it take to fill with n bytes of data */
#define CALC_N_BLOCKS(n) ((n / (block_data_size_bytes + 1)) + 1)

ssize_t brfs_read_block_offset(uint64_t block_idx, void *buf, size_t n,
                               size_t offset);

ssize_t brfs_read_block(uint64_t block_idx, void *buf, size_t n);

ssize_t brfs_write_block_offset(uint64_t block_idx, const void *buf, size_t n,
                                size_t offset);

ssize_t brfs_write_block(uint64_t block_idx, const void *buf, size_t n);

uint64_t brfs_read_block_ptr(uint64_t block_idx);

void brfs_write_block_ptr(uint64_t block_idx, size_t next_pointer);

uint64_t brfs_resolve_next_ptr(uint64_t block_idx);

/**
 * @brief properly advances `superblock->br_first_free`
 * @return size_t `brfs_read_block_ptr(superblock->br_first_free)`
 */
uint64_t brfs_advance_next_ptr();

/** Return 1 if `next_blkid == curr_blkid + 1`, otherwise return next_blkid */
#define brfs_blockptr_resolve_diff(curr_blkid, next_blkid)                     \
    ((curr_blkid + 1 == next_blkid) ? 1 : next_blkid)

ssize_t brfs_read(const brfs_dir_entry_64_t *entry, void *buf);

ssize_t brfs_write(const void *buf, size_t n);

ssize_t brfs_write_file_offset(const brfs_dir_entry_64_t *file, const void *buf,
                               size_t n, size_t offset);

/** Walk a file and return the block after blocks_offsetted, or the first block
 * with a EOF pointer */
uint64_t brfs_file_get_nblock(const brfs_dir_entry_64_t *file_entry,
                              size_t                     blocks_offsetted);

/** Mark a file as deleted, and properly advances `superblock->br_first_free` */
void brfs_file_delete(const brfs_dir_entry_64_t *file_entry);

/** Return 0 if success, or errno if failed */
int brfs_file_truncate(brfs_dir_entry_64_t *file_entry, size_t length);

brfs_dir_entry_64_t *brfs_find_in_dir(const char *               filename,
                                      const brfs_dir_entry_64_t *dir,
                                      size_t *foundon_offset);

char *getParentPath(const char *path);

char *basename(const char *path);

char *dirname(const char *path);

/*
 *
 */
int brfs_walk_tree(const char *path, brfs_dir_entry_64_t **entry,
                   brfs_dir_entry_64_t **parent_entry);

bool brfs_file_exists(const char *path);

brfs_dir_entry_64_t *brfs_new_entry(const char *nodname, uint64_t first_block,
                                    uint16_t mode, time_t creation_time);

/**
 * Write or modify (if already exists) an entry in a directory
 * @return 0 if success, errno otherwise
 */
int brfs_write_entry(const brfs_dir_entry_64_t *dir,
                     const brfs_dir_entry_64_t *new_entry);

int brfs_unlink_entry(const char *filename, brfs_dir_entry_64_t *dir,
                      brfs_dir_entry_64_t *parent_dir);

#endif // _BRFS_CORE_H
