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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../common/brfs.h"
#include "../common/log.h"

static const char BRFS_MAGIC_BYTES[4] = BRFS_MAGIC;


static uint32_t
ilog2(const uint32_t x) {
    int i = 31u;
    while ((!((x >> i) & 1)) && (i >= 0)) i--;
    return i;
}

void
print_usage(const char *self) {
    fprintf(stderr, "usage: %s device\n", self);
}

int
main(int argc, char **argv) {
    /* Defaults */
    int pointer_bits = 64;
    int block_size_bytes = 4096;


    if (argc < 2) {
        print_usage(argv[0]);
    }

    char *fsfile = argv[1];

    /* Check block size */
    if (block_size_bytes & (block_size_bytes - 1)) {
        aborterr(-1,"Error: Block size is not power of 2\n");
    }

    /* Check pointer size */
    if (!(pointer_bits == 16 || pointer_bits == 32 || pointer_bits == 64)) {
        aborterr(-1,"Error: Pointer size is not 16, 32 or 64\n");
    }


    int fsfd = open(fsfile, O_RDWR);
    if (fsfd < 0) {
        aborterr(-1, "Error opening file or device %s: %s\n", fsfile, strerror(errno));
    }

    struct stat st;
    if (fstat(fsfd, &st) < 0) {
        aborterr(-1, "Error stating file or device %s: %s\n", fsfile, strerror(errno));
    }

    void *mapped = NULL;
    if ((mapped = mmap(NULL, 2 * block_size_bytes, PROT_WRITE, MAP_SHARED, fsfd, 0)) == MAP_FAILED) {
        close(fsfd);
        aborterr(-1, "Error mmapping file or device %s: %s\n", fsfile, strerror(errno));
    }

    printf("Making BRFS filesystem in %s...\n", fsfile);
    printf("Parameters:\n\tBlock size: %d B\n\tPointer size: %d bits\n", block_size_bytes, pointer_bits);

    int total_blocks = st.st_size / block_size_bytes;

    printf("Device size: %d bytes, %d blocks, %d remaining bytes\n", st.st_size, total_blocks, st.st_size % block_size_bytes);

    if (pointer_bits == 16) {
        brfs_superblock_16_t *sb = (brfs_superblock_16_t*)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size = ilog2(block_size_bytes) - 8;
        sb->br_ptr_size = pointer_bits / 8;
    }
    else if (pointer_bits == 32) {
        brfs_superblock_32_t *sb = (brfs_superblock_32_t*)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size = ilog2(block_size_bytes) - 8;
        sb->br_ptr_size = pointer_bits / 8;
    }
    else if (pointer_bits == 64) {
        brfs_superblock_64_t *sb = (brfs_superblock_64_t*)mapped;
        memcpy(&sb->br_magic, BRFS_MAGIC_BYTES, 4);
        sb->br_block_size = ilog2(block_size_bytes) - 8;
        sb->br_ptr_size = pointer_bits / 8;
    }
    

    munmap(mapped, 2 * block_size_bytes);
    close(fsfd);

    return 0;
}
