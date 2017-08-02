package fscache

import (
	"os/user"
	"strconv"
)

var (
	userCache = make(map[string]uint32)
	uidCache  = make(map[uint32]string)

	groupCache = make(map[string]uint32)
	gidCache   = make(map[uint32]string)
)

func LookupUser(username string) (uint32, error) {
	if uid, ok := userCache[username]; ok {
		return uid, nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return 0, err
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	uid := uint32(uid64)
	userCache[username] = uid
	uidCache[uid] = username
	return uid, nil
}

func LookupUID(uid uint32) (string, error) {
	if username, ok := uidCache[uid]; ok {
		return username, nil
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	userCache[u.Name] = uid
	uidCache[uid] = u.Name
	return u.Name, nil
}

func LookupGroup(groupname string) (uint32, error) {
	if gid, ok := groupCache[groupname]; ok {
		return gid, nil
	}
	g, err := user.LookupGroup(groupname)
	if err != nil {
		return 0, err
	}
	gid64, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, err
	}
	gid := uint32(gid64)
	groupCache[groupname] = gid
	gidCache[gid] = groupname
	return gid, nil
}

func LookupGID(gid uint32) (string, error) {
	if groupname, ok := gidCache[gid]; ok {
		return groupname, nil
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return "", err
	}
	groupCache[g.Name] = gid
	gidCache[gid] = g.Name
	return g.Name, nil
}
