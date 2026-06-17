//go:build !unix

package secretfile

import "os"

type owner struct {
	uid int
	gid int
}

func fileOwner(os.FileInfo) (owner, bool) {
	return owner{}, false
}
