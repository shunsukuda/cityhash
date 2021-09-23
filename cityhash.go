package cityhash

import (
	"encoding/binary"
	"math/bits"
)

const (
	// Some primes between 2^63 and 2^64 for various uses.
	k0 uint64 = 0xc3a5c85c97cb3127
	k1 uint64 = 0xb492b66fbe98f273
	k2 uint64 = 0x9ae16a3b2f90404f

	// Magic numbers for 32-bit hashing.  Copied from murmur3.
	c1 uint32 = 0xcc9e2d51
	c2 uint32 = 0x1b873593
)

type Uint128 [2]uint64

// func NewUint128(lo, hi uint64) Uint128 { return Uint128{hi, lo} }
func (x Uint128) Low64() uint64        { return x[0] }
func (x Uint128) High64() uint64       { return x[1] }
func (x *Uint128) SetLow64(lx uint64)  { x[0] = lx }
func (x *Uint128) SetHigh64(hx uint64) { x[1] = hx }

func bswap32(x uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, x)
	return binary.LittleEndian.Uint32(b)
}

func bswap64(x uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, x)
	return binary.LittleEndian.Uint64(b)
}

func fetch32(p []byte) uint32 { return binary.LittleEndian.Uint32(p) }
func fetch64(p []byte) uint64 { return binary.LittleEndian.Uint64(p) }

func fmix(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// #define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)

func swap32(a, b *uint32) { *a, *b = *b, *a }
func swap64(a, b *uint64) { *a, *b = *b, *a }

func permute3(a, b, c *uint32) {
	swap32(a, b)
	swap32(a, c)
}

func mur(a, h uint32) uint32 {
	// Helper from murmur3 for combining two 32-bit values.
	a *= c1
	a = bits.RotateLeft32(a, -17)
	a *= c2
	h ^= a
	h = bits.RotateLeft32(h, -19)
	return h*5 + 0xe6546b64
}

func hash32Len13to24(s []byte, len uint32) uint32 {
	a := fetch32(s[(len>>1)-4:])
	b := fetch32(s[4:])
	c := fetch32(s[len-8:])
	d := fetch32(s[(len >> 1):])
	e := fetch32(s)
	f := fetch32(s[len-4:])
	h := len

	return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))))
}

func hash32Len0to4(s []byte, len uint32) uint32 {
	var b, c uint32 = 0, 9

	for i := range s[:len] {
		b = uint32(int64(b)*int64(c1) + int64(int8(s[i])))
		c ^= b
	}
	return fmix(mur(b, mur(len, c)))
}

func hash32Len5to12(s []byte, len uint32) uint32 {
	a, b, c := len, len*5, uint32(9)
	d := b

	a += fetch32(s)
	b += fetch32(s[len-4:])
	c += fetch32(s[((len >> 1) & 4):])
	return fmix(mur(c, mur(b, mur(a, d))))
}

// Hash function for a byte array.  Most useful in 32-bit binaries.
func CityHash32(s []byte, len uint32) uint32 {
	switch {
	case len <= 4:
		return hash32Len0to4(s, len)
	case len <= 12:
		return hash32Len5to12(s, len)
	case len <= 24:
		return hash32Len13to24(s, len)
	default:
	}

	// len > 24
	h, g := len, c1*len
	f := g
	a0 := bits.RotateLeft32(fetch32(s[len-4:])*c1, -17) * c2
	a1 := bits.RotateLeft32(fetch32(s[len-8:])*c1, -17) * c2
	a2 := bits.RotateLeft32(fetch32(s[len-16:])*c1, -17) * c2
	a3 := bits.RotateLeft32(fetch32(s[len-12:])*c1, -17) * c2
	a4 := bits.RotateLeft32(fetch32(s[len-20:])*c1, -17) * c2
	h ^= a0
	h = bits.RotateLeft32(h, -19)
	h = h*5 + 0xe6546b64
	h ^= a2
	h = bits.RotateLeft32(h, -19)
	h = h*5 + 0xe6546b64
	g ^= a1
	g = bits.RotateLeft32(g, -19)
	g = g*5 + 0xe6546b64
	g ^= a3
	g = bits.RotateLeft32(g, -19)
	g = g*5 + 0xe6546b64
	f += a4
	f = bits.RotateLeft32(f, -19)
	f = f*5 + 0xe6546b64

	iters := (len - 1) / 20
	for {
		a0 := bits.RotateLeft32(fetch32(s)*c1, -17) * c2
		a1 := fetch32(s[4:])
		a2 := bits.RotateLeft32(fetch32(s[8:])*c1, -17) * c2
		a3 := bits.RotateLeft32(fetch32(s[12:])*c1, -17) * c2
		a4 := fetch32(s[16:])
		h ^= a0
		h = bits.RotateLeft32(h, -18)
		h = h*5 + 0xe6546b64
		f += a1
		f = bits.RotateLeft32(f, -19)
		f = f * c1
		g += a2
		g = bits.RotateLeft32(g, -18)
		g = g*5 + 0xe6546b64
		h ^= a3 + a1
		h = bits.RotateLeft32(h, -19)
		h = h*5 + 0xe6546b64
		g ^= a4
		g = bswap32(g) * 5
		h += a4 * 5
		h = bswap32(h)
		f += a0
		permute3(&f, &h, &g)
		s = s[20:]

		iters--
		if iters == 0 {
			break
		}
	}
	g = bits.RotateLeft32(g, -11) * c1
	g = bits.RotateLeft32(g, -17) * c1
	f = bits.RotateLeft32(f, -11) * c1
	f = bits.RotateLeft32(f, -17) * c1
	h = bits.RotateLeft32(h+g, -19)
	h = h*5 + 0xe6546b64
	h = bits.RotateLeft32(h, -17) * c1
	h = bits.RotateLeft32(h+f, -19)
	h = h*5 + 0xe6546b64
	h = bits.RotateLeft32(h, -17) * c1
	return h
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
func hash128To64(x Uint128) uint64 {
	// murmur-inspired hashing.
	const kMul = 0x9ddfea08eb382d69
	a := (x.Low64() ^ x.High64()) * kMul
	a ^= (a >> 47)
	b := (x.High64() ^ a) * kMul
	b ^= (b >> 47)
	b *= kMul
	return b
}

func shiftMix(val uint64) uint64 { return val ^ (val >> 47) }

func hashLen16(u, v uint64) uint64 { return hash128To64(Uint128{u, v}) }

func hashLen16_2(u, v, mul uint64) uint64 {
	// Murmur-inspired hashing.
	a := (u ^ v) * mul
	a ^= (a >> 47)
	b := (v ^ a) * mul
	b ^= (b >> 47)
	b *= mul
	return b
}

func hashLen0to16(s []byte, len uint32) uint64 {
	if len >= 8 {
		mul := k2 + uint64(len)*2
		a := fetch64(s) + k2
		b := fetch64(s[len-8:])
		c := bits.RotateLeft64(b, -37)*mul + a
		d := (bits.RotateLeft64(a, -25) + b) * mul
		return hashLen16_2(c, d, mul)
	}
	if len >= 4 {
		mul := k2 + uint64(len)*2
		a := uint64(fetch32(s))
		return hashLen16_2(uint64(len)+(a<<3), uint64(fetch32(s[len-4:])), mul)
	}
	if len > 0 {
		a := s[0]
		b := s[len>>1]
		c := s[len-1]
		y := uint32(a) + (uint32(b) << 8)
		z := len + (uint32(c) << 2)
		return shiftMix(uint64(y)*k2^uint64(z)*k0) * k2
	}
	return k2
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
func hashLen17to32(s []byte, len uint32) uint64 {
	mul := k2 + uint64(len)*2
	a := fetch64(s) * k1
	b := fetch64(s[8:])
	c := fetch64(s[len-8:]) * mul
	d := fetch64(s[len-16:]) * k2
	return hashLen16_2(bits.RotateLeft64(a+b, -43)+bits.RotateLeft64(c, -30)+d,
		a+bits.RotateLeft64(b+k2, -18)+c, mul)
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
func weakHashLen32WithSeeds(w, x, y, z, a, b uint64) Uint128 {
	a += w
	b = bits.RotateLeft64(b+a+z, -21)
	c := a
	a += x
	a += y
	b += bits.RotateLeft64(a, -44)
	return Uint128{a + z, b + c}
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
func weakHashLen32WithSeeds_2(s []byte, a, b uint64) Uint128 {
	return weakHashLen32WithSeeds(fetch64(s), fetch64(s[8:]), fetch64(s[16:]), fetch64(s[24:]), a, b)
}

// Return an 8-byte hash for 33 to 64 bytes.
func hashLen33to64(s []byte, len uint32) uint64 {
	var mul uint64 = k2 + uint64(len)*2
	a := fetch64(s) * k2
	b := fetch64(s[8:])
	c := fetch64(s[len-24:])
	d := fetch64(s[len-32:])
	e := fetch64(s[16:]) * k2
	f := fetch64(s[24:]) * 9
	g := fetch64(s[len-8:])
	h := fetch64(s[len-16:]) * mul
	u := bits.RotateLeft64(a+g, -43) + (bits.RotateLeft64(b, -30)+c)*9
	v := ((a + g) ^ d) + f + 1
	w := bswap64((u+v)*mul) + h
	x := bits.RotateLeft64(e+f, -42) + c
	y := (bswap64((v+w)*mul) + g) * mul
	z := e + f + c
	a = bswap64((x+z)*mul+y) + b
	b = shiftMix((z+a)*mul+d+h) * mul
	return b + x
}

// Hash function for a byte array.
func CityHash64(s []byte, len uint32) uint64 {
	if len <= 32 {
		if len <= 16 {
			return hashLen0to16(s, len)
		} else {
			return hashLen17to32(s, len)
		}
	} else if len <= 64 {
		return hashLen33to64(s, len)
	}

	// For strings over 64 bytes we hash the end first, and then as we
	// loop we keep 56 bytes of state: v, w, x, y, and z.
	x := fetch64(s[len-40:])
	y := fetch64(s[len-16:]) + fetch64(s[len-56:])
	z := hashLen16(fetch64(s[len-48:])+uint64(len), fetch64(s[len-24:]))
	v := weakHashLen32WithSeeds_2(s[len-64:], uint64(len), z)
	w := weakHashLen32WithSeeds_2(s[len-32:], y+k1, x)
	x = x*k1 + fetch64(s)

	// Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
	len = (len - 1) & ^uint32(63)
	for {
		x = bits.RotateLeft64(x+y+v.Low64()+fetch64(s[8:]), -37) * k1
		y = bits.RotateLeft64(y+v.High64()+fetch64(s[48:]), -42) * k1
		x ^= w.High64()
		y += v.Low64() + fetch64(s[40:])
		z = bits.RotateLeft64(z+w.Low64(), -33) * k1
		v = weakHashLen32WithSeeds_2(s, v.High64()*k1, x+w.Low64())
		w = weakHashLen32WithSeeds_2(s[32:], z+w.High64(), y+fetch64(s[16:]))
		swap64(&z, &x)
		s = s[64:]
		len -= 64

		if len == 0 {
			break
		}
	}
	return hashLen16(hashLen16(v.Low64(), w.Low64())+shiftMix(y)*k1+z,
		hashLen16(v.High64(), w.High64())+x)
}

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
func CityHash64WithSeed(s []byte, len uint32, seed uint64) uint64 {
	return CityHash64WithSeeds(s, len, k2, seed)
}

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
func CityHash64WithSeeds(s []byte, len uint32, seed0, seed1 uint64) uint64 {
	return hashLen16(CityHash64(s, len)-seed0, seed1)
}

// A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
// of any length representable in signed long.  Based on City and Murmur.
func cityMurmur(s []byte, len uint32, seed Uint128) Uint128 {
	a := seed.Low64()
	b := seed.High64()
	var c, d uint64 = 0, 0
	l := int32(len) - 16

	if l <= 0 { // len <= 16
		a = shiftMix(a*k1) * k1
		c = b*k1 + hashLen0to16(s, len)
		if len >= 8 {
			d = shiftMix(a + fetch64(s))
		} else {
			d = shiftMix(a + c)
		}
	} else { // len > 16
		c = hashLen16(fetch64(s[len-8:])+k1, a)
		d = hashLen16(b+uint64(len), c+fetch64(s[len-16:]))
		a += d
		for {
			a ^= shiftMix(fetch64(s)*k1) * k1
			a *= k1
			b ^= a
			c ^= shiftMix(fetch64(s[8:])*k1) * k1
			c *= k1
			d ^= c
			s = s[16:]
			l -= 16

			if l <= 0 {
				break
			}
		}
	}
	a = hashLen16(a, c)
	b = hashLen16(d, b)
	return Uint128{a ^ b, hashLen16(b, a)}
}

// Hash function for a byte array.  For convenience, a 128-bit seed is also
// hashed into the result.
func CityHash128WithSeed(s []byte, len uint32, seed Uint128) Uint128 {
	if len < 128 {
		return cityMurmur(s, len, seed)
	}

	var t []byte = s
	original_len := len

	// We expect len >= 128 to be the common case.  Keep 56 bytes of state:
	// v, w, x, y, and z.
	var v, w Uint128
	x := seed.Low64()
	y := seed.High64()
	z := uint64(len) * k1
	v.SetLow64(bits.RotateLeft64(y^k1, -49)*k1 + fetch64(s))
	v.SetHigh64(bits.RotateLeft64(v.Low64(), -42)*k1 + fetch64(s[8:]))
	w.SetLow64(bits.RotateLeft64(y+z, -35)*k1 + x)
	w.SetHigh64(bits.RotateLeft64(x+fetch64(s[88:]), -53) * k1)

	// This is the same inner loop as CityHash64(), manually unrolled.
	for {
		x = bits.RotateLeft64(x+y+v.Low64()+fetch64(s[8:]), -37) * k1
		y = bits.RotateLeft64(y+v.High64()+fetch64(s[48:]), -42) * k1
		x ^= w.High64()
		y += v.Low64() + fetch64(s[40:])
		z = bits.RotateLeft64(z+w.Low64(), -33) * k1
		v = weakHashLen32WithSeeds_2(s, v.High64()*k1, x+w.Low64())
		w = weakHashLen32WithSeeds_2(s[32:], z+w.High64(), y+fetch64(s[16:]))
		swap64(&z, &x)
		s = s[64:]
		x = bits.RotateLeft64(x+y+v.Low64()+fetch64(s[8:]), -37) * k1
		y = bits.RotateLeft64(y+v.High64()+fetch64(s[48:]), -42) * k1
		x ^= w.High64()
		y += v.Low64() + fetch64(s[40:])
		z = bits.RotateLeft64(z+w.Low64(), -33) * k1
		v = weakHashLen32WithSeeds_2(s, v.High64()*k1, x+w.Low64())
		w = weakHashLen32WithSeeds_2(s[32:], z+w.High64(), y+fetch64(s[16:]))
		swap64(&z, &x)
		s = s[64:]
		len -= 128

		if len < 128 {
			break
		}
	}
	x += bits.RotateLeft64(v.Low64()+z, -49) * k0
	y = y*k0 + bits.RotateLeft64(w.High64(), -37)
	z = z*k0 + bits.RotateLeft64(w.Low64(), -27)
	w.SetLow64(w.Low64() * 9)
	v.SetLow64(v.Low64() * k0)

	// If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
	var tail_done uint32
	for tail_done = 0; tail_done < len; {
		tail_done += 32
		y = bits.RotateLeft64(x+y, -42)*k0 + v.High64()
		w.SetLow64(w.Low64() + fetch64(t[original_len-tail_done+16:]))
		x = x*k0 + w.Low64()
		z += w.High64() + fetch64(t[original_len-tail_done:])
		w.SetHigh64(w.High64() + v.Low64())
		v = weakHashLen32WithSeeds_2(t[original_len-tail_done:], v.Low64()+z, v.High64())
		v.SetLow64(v.Low64() * k0)
	}
	// At this point our 56 bytes of state should contain more than
	// enough information for a strong 128-bit hash.  We use two
	// different 56-byte-to-8-byte hashes to get a 16-byte final result.
	x = hashLen16(x, v.Low64())
	y = hashLen16(y+z, w.Low64())
	return Uint128{hashLen16(x+v.High64(), w.High64()) + y,
		hashLen16(x+w.High64(), y+v.High64())}
}

// Hash function for a byte array.
func CityHash128(s []byte, len uint32) Uint128 {
	if len >= 16 {
		return CityHash128WithSeed(s[16:len], len-16, Uint128{fetch64(s), fetch64(s[8:len]) + k0})
	} else {
		return CityHash128WithSeed(s, len, Uint128{k0, k1})
	}
}
