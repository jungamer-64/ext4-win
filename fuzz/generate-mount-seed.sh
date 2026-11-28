#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
    echo "usage: sh fuzz/generate-mount-seed.sh NEW_IMAGE_PATH" >&2
    exit 2
fi

version=$(mke2fs -V 2>&1)
case "$version" in
    'mke2fs 1.44.5 '*) ;;
    *) echo "the tracked mount seed was generated with e2fsprogs 1.44.5" >&2; exit 1 ;;
esac

output=$1
case "$output" in
    /* | ./* | ../*) ;;
    *) output=./$output ;;
esac
MKE2FS_CONFIG=/dev/null E2FSPROGS_FAKE_TIME=1700000000 \
    mke2fs -q -F -t ext4 -b 1024 -I 256 -N 128 -m 0 -J size=1 \
    -U 23ba6e33-45a3-40ed-8a2f-0742be3f2774 \
    -E lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=dad22cbb-97c3-46e5-af71-abbbbc7aa587 \
    -O none,has_journal,ext_attr,dir_index,filetype,extent,sparse_super,large_file \
    "$output" 4096
e2fsck -fn "$output"
