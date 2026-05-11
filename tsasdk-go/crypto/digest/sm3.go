// Package sm3 implements the SM3 cryptographic hash function defined
// in GB/T 32905-2016 (Chinese National Standard).
package digest

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	// Size is the size in bytes of a SM3 checksum.
	Size = 32
	// BlockSize is the block size in bytes of the SM3 hash function.
	BlockSize = 64
)

type digest struct {
	h   [8]uint32
	x   [BlockSize]byte
	nx  int
	len uint64
}

func newDigest() *digest {
	d := new(digest)
	d.Reset()
	return d
}

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	return newDigest()
}

func (d *digest) Reset() {
	d.h[0] = 0x7380166f
	d.h[1] = 0x4914b2b9
	d.h[2] = 0x172442d7
	d.h[3] = 0xda8a0600
	d.h[4] = 0xa96f30bc
	d.h[5] = 0x163138aa
	d.h[6] = 0xe38dee4d
	d.h[7] = 0xb0fb0e4e
	d.nx = 0
	d.len = 0
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)

	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		p = p[n:]
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
	}

	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}

	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	// Pad
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits
	len <<= 3
	var lenBytes [8]byte
	binary.BigEndian.PutUint64(lenBytes[:], len)
	d.Write(lenBytes[:])

	if d.nx != 0 {
		panic("sm3: not fully consumed")
	}

	var digest [Size]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(digest[i*4:], d.h[i])
	}
	return digest
}

func block(d *digest, p []byte) {
	var w [68]uint32
	var w1 [64]uint32

	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[i*4:])
	}

	for j := 16; j < 68; j++ {
		w[j] = p1(w[j-16]^w[j-9]^rotateLeft(w[j-3], 15)) ^ rotateLeft(w[j-13], 7) ^ w[j-6]
	}

	for j := 0; j < 64; j++ {
		w1[j] = w[j] ^ w[j+4]
	}

	a, b, c, dd, e, f, g, h :=
		d.h[0], d.h[1], d.h[2], d.h[3],
		d.h[4], d.h[5], d.h[6], d.h[7]

	for j := 0; j < 16; j++ {
		ss1 := rotateLeft(rotateLeft(a, 12)+e+rotateLeft(0x79cc4519, uint32(j)), 7)
		ss2 := ss1 ^ rotateLeft(a, 12)
		tt1 := ff0(a, b, c) + dd + ss2 + w1[j]
		tt2 := gg0(e, f, g) + h + ss1 + w[j]
		dd = c
		c = rotateLeft(b, 9)
		b = a
		a = tt1
		h = g
		g = rotateLeft(f, 19)
		f = e
		e = p0(tt2)
	}

	for j := 16; j < 64; j++ {
		ss1 := rotateLeft(rotateLeft(a, 12)+e+rotateLeft(0x7a879d8a, uint32(j)), 7)
		ss2 := ss1 ^ rotateLeft(a, 12)
		tt1 := ff1(a, b, c) + dd + ss2 + w1[j]
		tt2 := gg1(e, f, g) + h + ss1 + w[j]
		dd = c
		c = rotateLeft(b, 9)
		b = a
		a = tt1
		h = g
		g = rotateLeft(f, 19)
		f = e
		e = p0(tt2)
	}

	d.h[0] ^= a
	d.h[1] ^= b
	d.h[2] ^= c
	d.h[3] ^= dd
	d.h[4] ^= e
	d.h[5] ^= f
	d.h[6] ^= g
	d.h[7] ^= h
}

func rotateLeft(x uint32, n uint32) uint32 {
	return bits.RotateLeft32(x, int(n))
}

func p0(x uint32) uint32 {
	return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17)
}

func p1(x uint32) uint32 {
	return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23)
}

func ff0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func ff1(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func gg0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func gg1(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	d := newDigest()
	d.Write(data)
	return d.checkSum()
}
