//go:build unix

package enum

import "syscall"

// openRefFlags open a ref file without following a final symlink and
// without blocking on a FIFO (R7 I-1).
const openRefFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// openNoFollow reports that openRefFlags refuse a final symlink.
const openNoFollow = true
