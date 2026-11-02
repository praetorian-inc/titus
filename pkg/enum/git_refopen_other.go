//go:build !unix

package enum

// openRefFlags is empty where the platform has no O_NOFOLLOW (Windows, js).
// readRefFile then rejects a symlink with Lstat before the open, which
// leaves a window between the two calls; the fstat after the open still
// rejects a file that is not regular.
const openRefFlags = 0

// openNoFollow reports that an open follows a final symlink here.
const openNoFollow = false
