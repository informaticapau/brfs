cmake_minimum_required(VERSION 3.10)

project(brfs)

find_package(PkgConfig)
pkg_check_modules(FUSE fuse)

file (GLOB FUSE_SRC
    "brfs-fuse/brfs_fuse.c"
)

add_executable(brfs-fuse ${FUSE_SRC})

target_link_libraries(brfs-fuse ${FUSE_LIBRARIES})