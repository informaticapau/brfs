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

    brfs_mkfs.c: BRFS filesystem creation utility
*/

#include <bits/stdint-uintn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../common/brfs.h"
#include "../common/log.h"

/** Not a very fan of this, please use it wisely */
#define CREATE_ROOT_ENTRY(root_ent, mode, uid, gid, creation_time)             \
    root_ent->br_file_size =                                                   \
        block_size_bytes; /* Root start size is 1 block */                     \
                                                                               \
    root_ent->br_attributes.br_uid    = uid;                                   \
    root_ent->br_attributes.br_gid    = gid;                                   \
    root_ent->br_attributes.br_mode   = S_IFDIR | mode; /* (octal) */          \
    root_ent->br_attributes.br_crtime = creation_time;                         \
    root_ent->br_attributes.br_mtime  = creation_time;                         \
    root_ent->br_attributes.br_atime  = creation_time;                         \
                                                                               \
    root_ent->br_first_block = 1u;                                             \
                                                                               \
    char *filename = (char *)&root_ent->br_file_name_firstc;                   \
    strcpy(filename, "/");                                                     \
    ((char *)mapped)[block_size_bytes] = '\0'; /* Empty directory */

static const char BRFS_MAGIC_BYTES[4] = BRFS_MAGIC;

static uint32_t
ilog2(const uint32_t x) {
    int i = 31u;
    while ((!((x >> i) & 1)) && (i >= 0))
        i--;
    return i;
}

void
print_usage(const char *self) {
    fprintf(stderr, "usage: %s device\n", self);
}

int
main(int argc, char **argv) {
    /* Defaults */
    int pointer_bits     = 64;
    int pointer_bytes    = pointer_bits / 8;
    int block_size_bytes = 512;

    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    char *fsfile = argv[1];

    /* Check block size */
    if (block_size_bytes & (block_size_bytes - 1)) {
        aborterr(-1, "Error: Block size is not power of 2\n");
    }

    /* Check pointer size */
    if (!(pointer_bits == 16 || pointer_bits == 32 || pointer_bits == 64)) {
        aborterr(-1, "Error: Pointer size is not 16, 32 or 64\n");
    }

    int fsfd = open(fsfile, O_RDWR);
    if (fsfd < 0) {
        aborterr(-1, "Error opening file or device %s: %s\n", fsfile,
                 strerror(errno));
    }

    struct stat st;
    if (fstat(fsfd, &st) < 0) {
        aborterr(-1, "Error stating file or device %s: %s\n", fsfile,
                 strerror(errno));
    }

    void *mapped = NULL;
    if ((mapped = mmap(NULL, 2 * block_size_bytes, PROT_WRITE, MAP_SHARED, fsfd,
                       0)) == MAP_FAILED) {
        close(fsfd);
        aborterr(-1, "Error mmapping file or device %s: %s\n", fsfile,
                 strerror(errno));
    }

    int total_blocks = st.st_size / block_size_bytes;
    if (pointer_bits == 16 && total_blocks > UINT16_MAX)
        aborterr(-1, "Device too small for 16-bit BRFS\n");
    else if (pointer_bits == 32 && total_blocks > UINT32_MAX)
        aborterr(-1, "Device too small for 32-bit BRFS\n");
    else if (pointer_bits == 64 && total_blocks > UINT64_MAX)
        aborterr(-1, "Device too small for 64-bit BRFS\n");

    printf("Making BRFS filesystem in %s...\n", fsfile);
    printf("Parameters:\n\tBlock size: %d B\n\tPointer size: %d bits\n",
           block_size_bytes, pointer_bits);
    printf("Device size: %ld bytes, %d blocks, %ld remaining bytes\n",
           st.st_size, total_blocks, st.st_size % block_size_bytes);

    time_t creation_time = time(NULL);
    printf("Created at %d\n", (uint32_t)creation_time);

    /** The size of a block in powers of 2, minimum 512 (2^9) */
    uint8_t block_size_power = ilog2(block_size_bytes) - 9;

    /* Write superblock */
    if (pointer_bits == 16) {
        brfs_superblock_16_t *sb = (brfs_superblock_16_t *)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size  = block_size_power;
        sb->br_ptr_size    = pointer_bytes;
        sb->br_fs_size     = total_blocks;
        sb->br_free_blocks = total_blocks - 2;
        sb->br_first_free  = 2u;

        brfs_dir_entry_16_t *root_ent = (brfs_dir_entry_16_t *)&sb->br_root_ent;
        CREATE_ROOT_ENTRY(root_ent, 0755, getuid(), getgid(), creation_time)
    } else if (pointer_bits == 32) {
        brfs_superblock_32_t *sb = (brfs_superblock_32_t *)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size  = block_size_power;
        sb->br_ptr_size    = pointer_bytes;
        sb->br_fs_size     = total_blocks;
        sb->br_free_blocks = total_blocks - 2;
        sb->br_first_free  = 2u;

        brfs_dir_entry_32_t *root_ent = (brfs_dir_entry_32_t *)&sb->br_root_ent;
        CREATE_ROOT_ENTRY(root_ent, 0755, getuid(), getgid(), creation_time)
    } else if (pointer_bits == 64) {
        brfs_superblock_64_t *sb = (brfs_superblock_64_t *)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size  = block_size_power;
        sb->br_ptr_size    = pointer_bytes;
        sb->br_fs_size     = total_blocks;
        sb->br_free_blocks = total_blocks - 2;
        sb->br_first_free  = 2u;

        brfs_dir_entry_64_t *root_ent = (brfs_dir_entry_64_t *)&sb->br_root_ent;
        CREATE_ROOT_ENTRY(root_ent, 0755, getuid(), getgid(), creation_time)
    }

    // Put a NULL pointer at the end of ROOT
    memset((void *)(mapped + block_size_bytes * 2 - pointer_bytes), 0,
           pointer_bytes);

    munmap(mapped, 2 * block_size_bytes);
    close(fsfd);

    return 0;
}
