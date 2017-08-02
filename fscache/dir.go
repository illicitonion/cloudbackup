package fscache

import "os"

var dirCache = make(map[string]bool)

func Exists(path string) bool {
	if dirCache[path] {
		return true
	}

	_, err := os.Stat(path)
	if err == nil {
		dirCache[path] = true
		return true
	}
	return false
}
