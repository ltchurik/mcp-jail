//go:build windows

package sandbox

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	procGetNamedSecurityInfo = modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procGetAce               = modAdvapi32.NewProc("GetAce")
	procEqualSid             = modAdvapi32.NewProc("EqualSid")
)

const (
	seFileObject            = 1
	daclSecurityInformation = 0x00000004
	accessAllowedAceType    = 0
	inheritOnlyAce          = 0x08
	fileReadAttributes      = 0x0080
	genericRead             = 0x80000000
	genericAll              = 0x10000000
	allApplicationPackages  = "S-1-15-2-1"
)

type aclHeader struct {
	Revision, Sbz1 byte
	Size, AceCount uint16
	Sbz2           uint16
}

type accessAllowedAce struct {
	Type, Flags byte
	Size        uint16
	Mask        uint32
	SidStart    uint32
}

// packagesCanStat reports whether an AppContainer may read dir's
// attributes: an allow entry for ALL APPLICATION PACKAGES on the directory
// itself (not inherit-only) with read-attributes, generic read or all.
// Windows puts none on `C:\` and `C:\Users`, which every realpath walks.
func packagesCanStat(dir string) (bool, error) {
	p16, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return false, err
	}
	var dacl *aclHeader
	var sd uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p16)), seFileObject, daclSecurityInformation,
		0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd))); r != 0 {
		return false, fmt.Errorf("GetNamedSecurityInfo %s: error %d", dir, r)
	}
	defer func() { _, _, _ = procLocalFree.Call(sd) }()
	if dacl == nil {
		return true, nil // a null DACL grants everyone everything
	}
	s16, _ := syscall.UTF16PtrFromString(allApplicationPackages)
	var aap uintptr
	if r, _, e := procConvertStringSidToSid.Call(uintptr(unsafe.Pointer(s16)), uintptr(unsafe.Pointer(&aap))); r == 0 {
		return false, e
	}
	defer func() { _, _, _ = procLocalFree.Call(aap) }()
	for i := uintptr(0); i < uintptr(dacl.AceCount); i++ {
		var ace *accessAllowedAce
		if r, _, _ := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), i, uintptr(unsafe.Pointer(&ace))); r == 0 || ace == nil {
			continue
		}
		if ace.Type != accessAllowedAceType || ace.Flags&inheritOnlyAce != 0 || ace.Mask&(fileReadAttributes|genericRead|genericAll) == 0 {
			continue
		}
		if r, _, _ := procEqualSid.Call(uintptr(unsafe.Pointer(&ace.SidStart)), aap); r != 0 {
			return true, nil
		}
	}
	return false, nil
}

// RootStatNotes says which of the directories above the given ones no
// package may stat: the volume roots and the profiles root. A path walked
// from the root (node's realpath, so node itself and any server that
// resolves its own location) fails there, so the note names the one-time
// administrator command that allows it.
func RootStatNotes(dirs []string, home string) []string {
	seen := map[string]bool{}
	var roots []string
	for _, d := range dirs {
		if v := filepath.VolumeName(d); v != "" && !seen[v+`\`] {
			seen[v+`\`] = true
			roots = append(roots, v+`\`)
		}
	}
	if home != "" {
		if p := filepath.Dir(filepath.Clean(home)); p != filepath.Dir(p) && !seen[p] {
			roots = append(roots, p)
		}
	}
	var notes []string
	for _, r := range roots {
		ok, err := packagesCanStat(r)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: cannot read its ACL (%v)", r, err))
		} else if !ok {
			notes = append(notes, fmt.Sprintf("%s grants no package read-attributes, a path walked from there (node's realpath) fails in the container; once, as administrator: icacls %s /grant *%s:(RA)", r, r, allApplicationPackages))
		}
	}
	return notes
}
