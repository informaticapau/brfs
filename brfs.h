/*
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

    brfs.h: BRFS Specified structure definitions
*/

#ifndef _BRFS_H
#define _BRFS_H

#include <stdint.h>

/* Superblock up to ptr_size dependent fields */
typedef struct brfs_superblock_base {
    char        magic[4];
    uint32_t    block_size;
    uint8_t     ptr_size; 
} brfs_superblock_base_t;

/* 16-bit pointer superblock */
typedef struct brfs_superblock_16 {
    char        magic[4];
    uint32_t    block_size;
    uint8_t     ptr_size;
    uint16_t    free_space;
    uint16_t    first_free_block;
} brfs_superblock_16_t;

/* 32-bit pointer superblock */
typedef struct brfs_superblock_32 {
    char        magic[4];
    uint32_t    block_size;
    uint8_t     ptr_size;
    uint32_t    free_space;
    uint32_t    first_free_block;
} brfs_superblock_32_t;

/* 64-bit pointer superblock */
typedef struct brfs_superblock_64 {
    char        magic[4];
    uint32_t    block_size;
    uint8_t     ptr_size;
    uint64_t    free_space;
    uint64_t    first_free_block;
} brfs_superblock_64_t;


/* Directory entry attributes */
typedef struct brfs_attr {
    uint16_t    mode;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    crtime;
    uint32_t    atime;
    uint32_t    mtime;
} brfs_attr_t;

/* 16-bit pointer directory entry */
typedef struct brfs_dir_entry_16 {
    uint64_t    file_size;
    brfs_attr_t attributes;
    uint16_t    first_block;
    char        file_name_firstc;
} brfs_dir_entry_16_t;

/* 32-bit pointer directory entry */
typedef struct brfs_dir_entry_32 {
    uint64_t    file_size;
    brfs_attr_t attributes;
    uint32_t    first_block;
    char        file_name_firstc;
} brfs_dir_entry_32_t;

/* 64-bit pointer directory entry */
typedef struct brfs_dir_entry_64 {
    uint64_t    file_size;
    brfs_attr_t attributes;
    uint64_t    first_block;
    char        file_name_firstc;
} brfs_dir_entry_64_t;

#endif
