package cityhash

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type City struct {
	buf  []byte
	hash []byte
	size int
}

type Option func(*City) error

func SetSize32() Option {
	return func(c *City) error {
		c.size = 4
		return nil
	}
}

func SetSize64() Option {
	return func(c *City) error {
		c.size = 8
		return nil
	}
}

func SetSize128() Option {
	return func(c *City) error {
		c.size = 16
		return nil
	}
}

func NewCity(s []byte, opts ...Option) *City {
	c := City{
		size: 8,
		buf:  s,
		hash: make([]byte, 0, 16),
	}

	for _, f := range opts {
		if f != nil {
			f(&c)
		}
	}
	return &c
}

func (c *City) sumToHash32(x uint32) {
	c.hash = c.hash[0:0]
	t := make([]byte, 4)
	binary.BigEndian.PutUint32(t, x)
	c.hash = append(c.hash, t...)
}

func (c *City) sumToHash64(x uint64) {
	c.hash = c.hash[0:0]
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, x)
	c.hash = append(c.hash, t...)
}

func (c *City) sumToHash128(x Uint128) {
	c.hash = c.hash[0:0]
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, x.High64())
	c.hash = append(c.hash, t...)
	binary.BigEndian.PutUint64(t, x.Low64())
	c.hash = append(c.hash, t...)
}

func (c *City) Set(s []byte) { c.buf = s }

func (c *City) Write(p []byte) (n int, err error) {

	if len(p) > 0 {
		buf := make([]byte, len(c.buf))
		copy(buf, c.buf)
		newlen := len(c.buf) + len(p)
		if newlen > cap(c.buf) {
			c.buf = make([]byte, 0, newlen)
		}
		c.buf = append(buf, p...)
	}
	return len(p), nil
}

func (c *City) SetSize32()  { c.size = 4 }
func (c *City) SetSize64()  { c.size = 8 }
func (c *City) SetSize128() { c.size = 16 }

func (c *City) Buf() []byte { return c.buf }

func (c *City) Size() int { return c.size }

func (c *City) BlockSize() int {
	l := len(c.buf)

	if l == 0 {
		return 0
	}

	switch c.size {
	case 4:
		if l <= 24 {
			return 1
		} else {
			return int(((l - 1) / 20)) + 1
		}
	case 8:
		return int(((l - 1) / 64)) + 1
	case 16:
		return int(((l) / 128)) + 1
	default:
		return 0
	}
}

func (c *City) Reset() {
	c.buf = c.buf[0:0]
	c.hash = c.hash[0:0]
	// c.size = 8
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (c *City) Sum(b []byte) []byte {
	var buf []byte
	if len(b) > 0 {
		newlen := len(c.buf) + len(b)
		if newlen > cap(c.buf) {
			buf = make([]byte, 0, newlen)
			copy(buf, c.buf)
		}
		buf = append(buf, b...)
	} else {
		buf = c.buf
	}

	l := uint32(len(buf))
	switch c.size {
	case 4:
		c.sumToHash32(CityHash32(buf, l))
	case 8:
		c.sumToHash64(CityHash64(buf, l))
	case 16:
		c.sumToHash128(CityHash128(buf, l))
	}
	return c.hash
}

func (c *City) Sum32() uint32 {
	c.size = 4
	v := CityHash32(c.buf, uint32(len(c.buf)))
	c.sumToHash32(v)
	return v
}

func (c *City) Sum64() uint64 {
	c.size = 8
	v := CityHash64(c.buf, uint32(len(c.buf)))
	c.sumToHash64(v)
	return v
}

func (c *City) Sum64WithSeed(seed uint64) uint64 {
	c.size = 8
	v := CityHash64WithSeed(c.buf, uint32(len(c.buf)), seed)
	c.sumToHash64(v)
	return v
}

func (c *City) Sum64WithSeeds(seed0, seed1 uint64) uint64 {
	c.size = 8
	v := CityHash64WithSeeds(c.buf, uint32(len(c.buf)), seed0, seed1)
	c.sumToHash64(v)
	return v
}

func (c *City) Sum128() Uint128 {
	c.size = 16
	v := CityHash128(c.buf, uint32(len(c.buf)))
	c.sumToHash128(v)
	return v
}

func (c *City) Sum128WithSeed(seed Uint128) Uint128 {
	c.size = 16
	v := CityHash128WithSeed(c.buf, uint32(len(c.buf)), seed)
	c.sumToHash128(v)
	return v
}

func (c *City) String() string {
	if len(c.hash) == 0 {
		c.Sum(nil)
	}

	f := "%0" + strconv.Itoa(c.size) + "x"
	return fmt.Sprintf(f, c.hash)
}
