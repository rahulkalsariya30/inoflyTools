#!/usr/bin/env bash
#
# SITL-only helper for BUG #7 (2026-06-04).
#
# Why this exists: PX4's mavlink_ftp prepends _root_dir (= PX4_ROOTFSDIR) to every
# requested path. On real NuttX hardware PX4_ROOTFSDIR is "" (empty), so the QGC
# custom controllers MUST send absolute /fs/microsd/inofly/... paths — a relative
# URI resolves cwd-relative on the FC and FTP returns FileNotFound. We fixed QGC to
# send absolute paths.
#
# In SITL, _root_dir = CONFIG_BOARD_ROOT_PATH = "." and the FC writes its files to
# rootfs/inofly/ (PX4_STORAGEDIR "/inofly"). The absolute path that FTP now builds
# in SITL is "./fs/microsd/inofly/..." — so SITL needs rootfs/fs/microsd/inofly to
# point at rootfs/inofly for the same absolute URI to resolve. This script makes
# that symlink. Re-run after any `rm -rf build/` or fresh rootfs regeneration.
# Idempotent.
#
# Usage: tools/sitl_ftp_symlink.sh [ROOTFS_DIR]
#   ROOTFS_DIR defaults to ~/PX4-Autopilot/build/px4_sitl_default/rootfs
set -euo pipefail

ROOTFS="${1:-$HOME/PX4-Autopilot/build/px4_sitl_default/rootfs}"

if [ ! -d "$ROOTFS" ]; then
	echo "error: SITL rootfs not found at $ROOTFS (build SITL first)" >&2
	exit 1
fi

mkdir -p "$ROOTFS/inofly" "$ROOTFS/fs/microsd"
# Target is resolved relative to the link's own directory (rootfs/fs/microsd/),
# so ../../inofly == rootfs/inofly. -n avoids descending into an existing link.
ln -sfn ../../inofly "$ROOTFS/fs/microsd/inofly"

echo "linked $ROOTFS/fs/microsd/inofly -> ../../inofly"
ls -la "$ROOTFS/fs/microsd/inofly"
