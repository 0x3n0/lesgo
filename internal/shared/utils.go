package shared

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI removes ANSI escape codes from a string.
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// NewAurora returns a colorized output helper.
func NewAurora(noColor bool) aurora.Aurora {
	return aurora.NewAurora(!noColor)
}

// TrimProtocol strips http:// and https:// prefixes.
func TrimProtocol(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	return strings.TrimRight(target, "/")
}

// IsURL checks if the target looks like a URL.
func IsURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// ExtractDomain extracts the domain from a URL.
func ExtractDomain(raw string) string {
	raw = TrimProtocol(raw)
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx != -1 {
		raw = raw[:idx]
	}
	return raw
}

// GetHash returns the requested hash of data.
func GetHash(hashType, data string) string {
	var h hash.Hash
	switch strings.ToLower(hashType) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "mmh3":
		return fmt.Sprintf("%d", int32(murmur3_32([]byte(data))))
	default:
		return ""
	}
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// RemoveURLDefaultPort removes default port 80/443 from URLs.
func RemoveURLDefaultPort(u string) string {
	if strings.HasSuffix(u, ":443") {
		return strings.TrimSuffix(u, ":443")
	}
	if strings.HasSuffix(u, ":80") {
		return strings.TrimSuffix(u, ":80")
	}
	return u
}

// AddURLDefaultPort adds default port back.
func AddURLDefaultPort(u string) string {
	if strings.HasPrefix(u, "https://") && !strings.Contains(u[8:], ":") {
		return u
	}
	return u
}

// HTTPGet performs a simple HTTP GET with timeout.
func HTTPGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// SplitByCharAndTrimSpace splits a string and trims whitespace from each element.
func SplitByCharAndTrimSpace(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// murmur3_32 implements the 32-bit x86 MurmurHash3 algorithm (seed 0).
func murmur3_32(data []byte) uint32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	const seed uint32 = 0

	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = rotl32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 = fmix32(h1)
	return h1
}

func rotl32(x uint32, r uint8) uint32 {
	return (x << r) | (x >> (32 - r))
}

func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
