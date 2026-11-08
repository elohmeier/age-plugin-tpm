//go:build !unix

package plugin

func checkPrivateDir(dir string) error { return nil }
