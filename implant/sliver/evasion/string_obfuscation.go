package evasion

/*
	Sliver Implant Framework
	Copyright (C) 2025  Bishop Fox

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
	"encoding/base64"
	"strings"
)

// ObfuscationKey is the XOR key for string de-obfuscation
var (
	obfuscationKey = []byte{0x5A, 0x3F, 0x2C, 0x7D}
	obfuscationEnabled = true
)

// SetStringObfuscation enables or disables string obfuscation at runtime
func SetStringObfuscation(enabled bool) {
	obfuscationEnabled = enabled
}

// IsStringObfuscationEnabled returns current status
func IsStringObfuscationEnabled() bool {
	return obfuscationEnabled
}

// xorString performs XOR operation on a string
func xorString(s string) []byte {
	if len(obfuscationKey) == 0 {
		return []byte(s)
	}

	keyLen := len(obfuscationKey)
	result := make([]byte, len(s))

	for i := 0; i < len(s); i++ {
		result[i] = s[i] ^ obfuscationKey[i%keyLen]
	}

	return result
}

// deobfuscateString reverses the XOR operation to retrieve original string
func DeobfuscateString(encrypted []byte) string {
	if !obfuscationEnabled {
		return string(encrypted)
	}

	if len(obfuscationKey) == 0 {
		return string(encrypted)
	}

	keyLen := len(obfuscationKey)
	result := make([]byte, len(encrypted))

	for i := 0; i < len(encrypted); i++ {
		result[i] = encrypted[i] ^ obfuscationKey[i%keyLen]
	}

	return string(result)
}

// ObfuscateString encrypts a string using XOR and returns base64 encoded result
// This is meant to be used at build time, not runtime
func ObfuscateString(s string) string {
	if s == "" {
		return ""
	}

	encrypted := xorString(s)
	return base64.StdEncoding.EncodeToString(encrypted)
}

// splitString splits a string into chunks to avoid static analysis
func SplitString(s string, chunkSize int) []string {
	if chunkSize <= 0 {
		chunkSize = 3
	}

	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}

	return chunks
}

// JoinSplitString reverses SplitString operation
func JoinSplitString(chunks []string) string {
	return strings.Join(chunks, "")
}

// Rot13 performs ROT13 cipher on a string (simple obfuscation technique)
func Rot13(s string) string {
	result := make([]byte, len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			// Shift by 13
			if (c >= 'a' && c <= 'z') {
				result[i] = 'a' + (c-'a'+13)%26
			} else {
				result[i] = 'A' + (c-'A'+13)%26
			}
		} else {
			result[i] = c
		}
	}

	return string(result)
}

// ObfuscatedDLLName represents an obfuscated DLL name
type ObfuscatedDLLName struct {
	obfuscated string
	chunks    []string
}

// NewObfuscatedDLLName creates a new obfuscated DLL name
func NewObfuscatedDLLName(dllName string) *ObfuscatedDLLName {
	// Split into chunks to break static analysis
	chunks := SplitString(dllName, 3)
	obfuscated := ObfuscateString(dllName)

	return &ObfuscatedDLLName{
		obfuscated: obfuscated,
		chunks:    chunks,
	}
}

// Deobfuscate retrieves the original DLL name
func (o *ObfuscatedDLLName) Deobfuscate() string {
	if !obfuscationEnabled {
		// Try joining chunks first
		original := JoinSplitString(o.chunks)
		if original != "" {
			return original
		}
	}

	// Fall back to XOR de-obfuscation
	decoded, err := base64.StdEncoding.DecodeString(o.obfuscated)
	if err != nil {
		return o.obfuscated
	}

	return DeobfuscateString(decoded)
}

// Common DLL names - these would be obfuscated at build time
// Using compile-time constants to avoid runtime string literals
const (
	// Obfuscated Windows DLL paths
	obfNtdllPath = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX0R5Y2h0b1x6Y29c"     // ntdll.dll
	obfKernel32Path = "QzpXaW5kb3dzX0x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX1R5Y2h0b1x6Y29c"  // kernel32.dll
	obfAmsiPath = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX0N0aXVpc1x4Y2xs"      // amsi.dll
	obfAdvapi32Path = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX1BkdmFwaTMyLmRs" // advapi32.dll
	obfUser32Path = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX1VzZXIzMi5kb"       // user32.dll
	obfDbgCorePath = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX0RkYmdDb3JyLmRs"          // dbgcore.dll
	obfGdi32Path = "QzpXaW5kb3dzX1x5a3JhXF0X0d0X1Rc1Jc3ZmRwc1x6YXRvX0dkaTMyLmRs"              // gdi32.dll
	obfNtdllDLL = "b3RkbGwuZGxs"                      // ntdll.dll
	obfKernel32DLL = "a2VybmVsMzIuZGxs"                  // kernel32.dll
	obfAmsiDLL = "YW1zaS5kbGw"                       // amsi.dll
	obfDbgCoreDLL = "RGJnQ29yZS5kbGw"                  // dbgcore.dll
	obfGdi32DLL = "Z2RpMzIuZGxs"                        // gdi32.dll
)

// GetNtdllPath returns the de-obfuscated path to ntdll.dll
func GetNtdllPath() string {
	return DeobfuscateDLLPath(obfNtdllPath)
}

// GetKernel32Path returns the de-obfuscated path to kernel32.dll
func GetKernel32Path() string {
	return DeobfuscateDLLPath(obfKernel32Path)
}

// GetAmsiPath returns the de-obfuscated path to amsi.dll
func GetAmsiPath() string {
	return DeobfuscateDLLPath(obfAmsiPath)
}

// GetAdvapi32Path returns the de-obfuscated path to advapi32.dll
func GetAdvapi32Path() string {
	return DeobfuscateDLLPath(obfAdvapi32Path)
}

// GetUser32Path returns the de-obfuscated path to user32.dll
func GetUser32Path() string {
	return DeobfuscateDLLPath(obfUser32Path)
}

// GetDbgCorePath returns the de-obfuscated path to dbgcore.dll
func GetDbgCorePath() string {
	return DeobfuscateDLLPath(obfDbgCorePath)
}

// GetGdi32Path returns the de-obfuscated path to gdi32.dll
func GetGdi32Path() string {
	return DeobfuscateDLLPath(obfGdi32Path)
}

// DeobfuscateDLLPath de-obfuscates a base64 encoded XOR encrypted path
func DeobfuscateDLLPath(obfuscatedPath string) string {
	if !obfuscationEnabled {
		// Return hardcoded strings when obfuscation is disabled
		switch obfuscatedPath {
		case obfNtdllPath:
			return "C:\\Windows\\System32\\ntdll.dll"
		case obfKernel32Path:
			return "C:\\Windows\\System32\\kernel32.dll"
		case obfAmsiPath:
			return "C:\\Windows\\System32\\amsi.dll"
		case obfAdvapi32Path:
			return "C:\\Windows\\System32\\advapi32.dll"
		case obfUser32Path:
			return "C:\\Windows\\System32\\user32.dll"
		case obfDbgCorePath:
			return "C:\\Windows\\System32\\dbgcore.dll"
		case obfGdi32Path:
			return "C:\\Windows\\System32\\gdi32.dll"
		}
	}

	// De-obfuscate using base64 + XOR
	decoded, err := base64.StdEncoding.DecodeString(obfuscatedPath)
	if err != nil {
		//{{if .Config.Debug}}
		// log.Printf("[!] Failed to decode obfuscated DLL path: %v\n", err)
		//{{end}}
		return obfuscatedPath
	}

	return DeobfuscateString(decoded)
}

// GetNtdllDLL returns the de-obfuscated DLL name for ntdll.dll
func GetNtdllDLL() string {
	return DeobfuscateString([]byte(obfNtdllDLL))
}

// GetKernel32DLL returns the de-obfuscated DLL name for kernel32.dll
func GetKernel32DLL() string {
	return DeobfuscateString([]byte(obfKernel32DLL))
}

// GetAmsiDLL returns the de-obfuscated DLL name for amsi.dll
func GetAmsiDLL() string {
	return DeobfuscateString([]byte(obfAmsiDLL))
}

// GetDbgCoreDLL returns the de-obfuscated DLL name for dbgcore.dll
func GetDbgCoreDLL() string {
	return DeobfuscateString([]byte(obfDbgCoreDLL))
}

// GetGdi32DLL returns the de-obfuscated DLL name for gdi32.dll
func GetGdi32DLL() string {
	return DeobfuscateString([]byte(obfGdi32DLL))
}

// ObfuscatedFunctionName represents an obfuscated function name
type ObfuscatedFunctionName struct {
	obfuscated string
	name      string
}

// Common Windows API function names
const (
	obfVirtualAlloc = "Vmlyd2FsbGxvYw=="        // VirtualAlloc
	obfCreateRemoteThread = "Q3JlYXRlUmVtb3RlVGhyZWFk" // CreateRemoteThread
	obfWriteProcessMemory = "V3JpdGVQcm9jZXNzTWVtb3J5"  // WriteProcessMemory
	obfVirtualProtect = "VmlydHVhbFByb3RlY3Q="       // VirtualProtect
	obfAmsiScanBuffer = "QW1zaVNjYW5CdWZmZmVy"       // AmsiScanBuffer
	obfAmsiInitialize = "QW1zaUluaXRpYWxpemU="          // AmsiInitialize
	obfAmsiScanString = "QW1zaVNjYW5TdHJpbmc="          // AmsiScanString
	obfEtwEventWrite = "RXR3RXZlbnRXcml0ZQ=="              // EtwEventWrite
)

// GetObfuscatedFunction returns an obfuscated function name wrapper
func GetObfuscatedFunction(fnName string) string {
	if !obfuscationEnabled {
		return fnName
	}

	// Map known function names to their obfuscated versions
	switch fnName {
	case "VirtualAlloc":
		return DeobfuscateString([]byte("Vmlyd2FsbGxvYw=="))
	case "CreateRemoteThread":
		return DeobfuscateString([]byte("Q3JlYXRlUmVtb3RlVGhyZWFk"))
	case "WriteProcessMemory":
		return DeobfuscateString([]byte("V3JpdGVQcm9jZXNzTWVtb3J5"))
	case "VirtualProtect":
		return DeobfuscateString([]byte("VmlydHVhbFByb3RlY3Q="))
	case "AmsiScanBuffer":
		return DeobfuscateString([]byte("QW1zaVNjYW5CdWZmZmVy"))
	case "AmsiInitialize":
		return DeobfuscateString([]byte("QW1zaUluaXRpYWxpemU="))
	case "AmsiScanString":
		return DeobfuscateString([]byte("QW1zaVNjYW5TdHJpbmc="))
	case "EtwEventWrite":
		return DeobfuscateString([]byte("RXR3RXZlbnRXcml0ZQ=="))
	}

	return fnName
}
