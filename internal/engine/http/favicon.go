package http

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// fetchFavicon downloads /favicon.ico and computes its mmh3 hash.
func (e *Engine) fetchFavicon(targetURL *url.URL) string {
	// Build favicon URL
	favURL := *targetURL
	favURL.Path = "/favicon.ico"
	favURL.RawQuery = ""

	client := &http.Client{
		Timeout: time.Duration(e.opts.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(favURL.String())
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(body) == 0 {
		return ""
	}

	// Compute mmh3 32-bit hash with seed 0
	hash := murmur3_32(body)
	return fmt.Sprintf("%d", int32(hash))
}

// murmur3_32 implements the 32-bit x86 MurmurHash3 algorithm.
// https://en.wikipedia.org/wiki/MurmurHash
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
