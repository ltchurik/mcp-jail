package ui

import (
	"io/fs"
	"os"
)

// osDirFS is indirected for tests.
var osDirFS = func(dir string) fs.FS { return os.DirFS(dir) }
