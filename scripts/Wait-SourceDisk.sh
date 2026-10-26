#!/bin/bash
set -euo pipefail
for attempt in $(seq 1 60); do
    if test -b /dev/disk/azure/scsi1/lun0; then
        test "$(blockdev --getsize64 /dev/disk/azure/scsi1/lun0)" = 32213303296
        echo SOURCE_DISK_READY
        exit 0
    fi
    sleep 5
done
echo 'The source disk did not attach within five minutes.' >&2
exit 1
