#!/bin/sh
# box xclip shim — serves the host-synced clipboard IMAGE to Claude Code.
#
# The real clipboard lives on the Mac; while a box runs, the host mirrors the
# clipboard's image content (images ONLY — text is never synced) into
# /run/box-clipboard/clipboard.png (see ClipboardSync.swift). There is no X
# server in the guest, so the real xclip could never work; this shim answers
# exactly the read operations Claude Code's Linux paste path performs:
#
#   xclip -selection clipboard -t TARGETS -o     → advertise image/png
#   xclip -selection clipboard -t image/png -o   → emit the PNG bytes
#
# Everything else — text reads, image/bmp, and WRITES (copy-to-clipboard) —
# reports failure, so callers degrade exactly as if no clipboard tool existed.
CLIP=/run/box-clipboard/clipboard.png

TYPE=
OUT=0
while [ $# -gt 0 ]; do
    case "$1" in
        -t|-target) TYPE="${2:-}"; shift; shift ;;
        -o|-out) OUT=1; shift ;;
        *) shift ;;
    esac
done

[ "$OUT" = 1 ] || exit 1  # write/copy: unsupported (clipboard is host-owned)

case "$TYPE" in
    TARGETS)
        [ -s "$CLIP" ] || exit 1
        echo "image/png"
        ;;
    image/png)
        [ -s "$CLIP" ] || exit 1
        exec cat "$CLIP"
        ;;
    *)
        exit 1
        ;;
esac
