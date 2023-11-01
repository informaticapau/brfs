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
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>

#define FUSE_USE_VERSION    26
#define _FILE_OFFSET_BITS   64
#include <fuse.h>

#include "../common/brfs.h"
#include "../common/log.h"

#define BRFS_FUSE_DATA (*((struct brfs_fuse_state*)fuse_get_context()->private_data))

void *
memdup(const void *mem, size_t size) { 
   void *out = malloc(size);

   if(out != NULL)
       memcpy(out, mem, size);

   return out;
}



int fsfd = 0;
brfs_superblock_64_t *superblock = NULL;

size_t
brfs_sizeof_dir_entry(const brfs_dir_entry_64_t *dir_entry) {
    return sizeof(brfs_dir_entry_64_t) + strlen(&dir_entry->br_file_name_firstc);
}

brfs_dir_entry_64_t *
brfs_find_in_dir(const char *file, brfs_dir_entry_64_t *dir_first,
                 size_t dir_size) {
    brfs_dir_entry_64_t *current_dir_entry = dir_first;
    while ((current_dir_entry - dir_first) < dir_size - sizeof(brfs_dir_entry_64_t)) {
        if (strcmp(file, &current_dir_entry->br_file_name_firstc) == 0) {
            return current_dir_entry;
        }
        current_dir_entry += brfs_sizeof_dir_entry(current_dir_entry);
    }
    return NULL;
}

int
brfs_read_dir(brfs_dir_entry_64_t *dir_entry, brfs_dir_entry_64_t **dir_buffer) {
    *dir_buffer =
        malloc(dir_entry->br_file_size);
    if (lseek(fsfd,
        superblock->br_block_size * dir_entry->br_first_block,
        SEEK_SET) < 0) {
        debug_log(1, "brfs_read_dir: lseek: %s\n", strerror(errno));
        free(dir_entry);
        return -1;
    }
    int readed = read(fsfd, dir_buffer, dir_entry->br_file_size);
    if (readed < 0) {
        debug_log(1, "brfs_read_dir: read: %s\n", strerror(errno));
        free(dir_entry);
        return -1;
    }
    return readed;
}

brfs_dir_entry_64_t *
brfs_walk_tree(const char *path) {
    if (*path != '/') {
        debug_log(1, "brfs_walk_tree: error: Path not absolute\n");
        return NULL;
    }
    if (strlen(path) == 1) {
        return memdup(&superblock->br_root_ent, sizeof(brfs_dir_entry_64_t));
    }

    brfs_dir_entry_64_t *prev_dir_entry = &superblock->br_root_ent;
    brfs_dir_entry_64_t *next_file = NULL;

    char *patht = strdup(path);
    char *tok = strtok(patht, "/");
    while (tok) {
        /* If prev is not dir */
        if (!S_ISDIR(prev_dir_entry->br_attributes.br_mode)) {
            debug_log(1, "brfs_walk_tree: Token not a directory: %s\n", tok);
            free(prev_dir_entry);
            return NULL;
        }

        /* Read directory */
        brfs_dir_entry_64_t *current_dir_first;
        if (brfs_read_dir(prev_dir_entry, &current_dir_first) < 0) {
            debug_log(1, "brfs_walk_tree: error brfs_read_dir on tok: %s\n", tok);
            free(prev_dir_entry);
            return NULL;
        }

        /* Find tok in directory */
        next_file = brfs_find_in_dir(tok,
            current_dir_first, prev_dir_entry->br_file_size);
        if (!next_file) {
                debug_log(1, "brfs_walk_tree: file does not exist: %s\n", path);
                free(prev_dir_entry);
                free(current_dir_first);
                return NULL;
        }

        /* Propagate tok */
        prev_dir_entry = memdup(next_file, brfs_sizeof_dir_entry(next_file));
        tok = strtok(NULL, "/");

        free(prev_dir_entry);
        free(current_dir_first);
    }

    /* Path propagated, next_file should be our file */
    return next_file;
}

/* ====================== FUSE OPERATIONS ======================*/

int
brfs_fuse_getattr(const char *path, struct stat *st) {
    debug_log(1, "getattr(\"%s\")\n", path);
    brfs_dir_entry_64_t *file_entry = brfs_walk_tree(path);
    if (!file_entry) {
        debug_log(1, "brfs_fuse_getattr: error brfs_walk_tree: %s\n", path);
        return -1;
    }

    st->st_uid = file_entry->br_attributes.br_uid;
    st->st_gid = file_entry->br_attributes.br_gid;
    st->st_mode = file_entry->br_attributes.br_mode;
    st->st_atime = file_entry->br_attributes.br_atime;
    st->st_mtime = file_entry->br_attributes.br_mtime;

    free(file_entry);
    return 0;
}

int
brfs_fuse_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi) {
    debug_log(1, "readdir(\"%s\")\n", path);

    /* Find directory */
    brfs_dir_entry_64_t *dir_entry = brfs_walk_tree(path);
    if (!dir_entry) return -1;

    /* Read directory */
    brfs_dir_entry_64_t *dir_first;
    if (brfs_read_dir(dir_entry, &dir_first) < 0) {
        debug_log(1, "brfs_fuse_readdir: error brfs_read_dir on path: %s\n", path);
        free(dir_entry);
        return -1;
    }

    filler(buffer, ".", NULL, 0);
	filler(buffer, "..", NULL, 0);

    const brfs_dir_entry_64_t *current_entry = dir_first;
    while ((dir_first - current_entry) < dir_entry->br_file_size - sizeof(brfs_dir_entry_64_t)) {
        filler(buffer, &current_entry->br_file_name_firstc, NULL, 0);
        current_entry += brfs_sizeof_dir_entry(current_entry);
    }

    return 0;
}

int
brfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    debug_log(1, "open(\"%s\")\n", path);
    return 0;
}

int
brfs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi) {
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
    
};

void
usage() {
    fprintf(stderr,
        "usage:  brfs-fuse [FUSE and mount options] device mount_point\n");
    abort();
}

int 
powi(int b, int e) {
    int t = b;
    while (e--) t *= b;
    return t;
}

int
main(int argc, char **argv) {
    struct brfs_fuse_state *brfs_fuse_data
        = malloc(sizeof(struct brfs_fuse_state));

    /* Check arguments */
    if ((argc < 3) || (argv[argc-1][0] == '-') || (argv[argc-2][0] == '-'))
	    usage();

    char *fsfile = argv[argc-2];
    char *mount_point = argv[argc-1];

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

    superblock = (brfs_superblock_64_t*)mapped;


    printf("Block size: %d\nPointer size: %d\nFS size: %d\nFree blocks: %d\nFirst free block: %d\n",
        powi(2, 8 + superblock->br_block_size), superblock->br_ptr_size,
        superblock->br_fs_size, superblock->br_free_blocks,
        superblock->br_first_free);

    /* FUSE main */

    int new_argc = 0;
    char *new_argv[100]; /* 100 max args */
    for (int i = 0; i < argc - 2; i++)
        new_argv[new_argc++] = argv[i];
    new_argv[new_argc++] = mount_point;
    new_argv[new_argc] = NULL;

    int fuse_ret = fuse_main(new_argc, new_argv, &brfs_operations,
        brfs_fuse_data);

    munmap(mapped, BRFS_SUPERBLOCK_MAX_SIZE);
    close(fsfd);

    return fuse_ret;
}
