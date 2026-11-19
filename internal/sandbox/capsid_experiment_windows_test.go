//go:build windows

package sandbox

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// TestCapabilitySidTable prints the SID of every known capability name so
// the ACEs Windows puts on C:\ and C:\Users can be matched to a name.
// Temporary experiment.
func TestCapabilitySidTable(t *testing.T) {
	if os.Getenv("MCP_JAIL_CAPSID_TABLE") == "" {
		t.Skip("experiment")
	}
	derive := syscall.NewLazyDLL("kernelbase.dll").NewProc("DeriveCapabilitySidsFromName")
	toStr := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertSidToStringSidW")
	names := []string{
		"lpacAppExperience", "lpacCom", "lpacCryptoServices", "lpacEnterprisePolicyChangeNotifications",
		"lpacIdentityServices", "lpacInstrumentation", "lpacMedia", "lpacPnPNotifications", "lpacPrinting",
		"lpacPayments", "lpacServicesManagement", "lpacSessionManagement", "lpacWebPlatform", "lpacDeviceAccess",
		"lpacCapabilityAccessManagement", "lpacClipboard", "lpacInternetClient", "registryRead", "internetClient",
		"internetClientServer", "privateNetworkClientServer", "documentsLibrary", "picturesLibrary", "videosLibrary",
		"musicLibrary", "removableStorage", "enterpriseAuthentication", "sharedUserCertificates", "appointments",
		"contacts", "userAccountInformation", "constrainedImpersonation", "packageContents", "packageQuery",
		"isolatedWin32-profile", "isolatedWin32-userProfileMinimal", "isolatedWin32-print", "isolatedWin32-sysTray",
		"isolatedWin32-promptForAccess", "isolatedWin32-accessToPublisherDirectory", "isolatedWin32-shellHWNotification",
		"isolatedWin32-profilesRootMinimal", "isolatedWin32-programFilesMinimal", "isolatedWin32-systemRootMinimal",
		"isolatedWin32-drivesRootMinimal", "isolatedWin32-usersFolderMinimal", "isolatedWin32-usersRootMinimal",
		"isolatedWin32-userProfile", "isolatedWin32-localAppData", "isolatedWin32-roamingAppData",
		"isolatedWin32-documentsFolder", "chromeInstallFiles", "lpacChromeInstallFiles", "broadFileSystemAccess",
		"runFullTrust", "allowElevation", "unvirtualizedResources", "uiAccess", "developmentModeNetwork",
		"inputForegroundObservation", "localSystemServices", "systemManagement", "isolatedWin32-usersMinimal",
		"isolatedWin32-driveRootMinimal", "isolatedWin32-profileMinimal", "isolatedWin32-profileRoot",
	}
	for _, n := range names {
		var groupSids, capSids *uintptr
		var nGroup, nCap uint32
		p, _ := syscall.UTF16PtrFromString(n)
		r, _, e := derive.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&groupSids)),
			uintptr(unsafe.Pointer(&nGroup)), uintptr(unsafe.Pointer(&capSids)), uintptr(unsafe.Pointer(&nCap)))
		if r == 0 {
			t.Logf("%-45s derive failed: %v", n, e)
			continue
		}
		sids := unsafe.Slice(capSids, nCap)
		for _, s := range sids {
			var str *uint16
			toStr.Call(s, uintptr(unsafe.Pointer(&str)))
			t.Logf("%-45s %s", n, syscall.UTF16ToString(unsafe.Slice(str, 200)))
		}
	}
}
