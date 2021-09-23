# CityHash

Google's CityHash.

https://github.com/google/cityhash


`City` implements `hash.Hash`.


```go
c := NewCity([]byte("..."))                   // Sum() = Sum64()
c32 := NewCity([]byte("..."), SetSize32())    // Sum() = Sum32() 
c64 := NewCity([]byte("..."), SetSize64())    // Sum() = Sum64()
c128 := NewCity([]byte("..."), SetSize128()) //  Sum() = Sum128()

c.SetSize32()  // Sum() = Sum32()
c.SetSize64()  // Sum() = Sum64()
c.SetSize128() // Sum() = Sum128()

c.Set([]byte("..."))    // set new []byte
c.Write([]byte("..."))  // append []byte

c.Sum32()                      // uint32
c.Sum64()                      // uint64
c.Sum64WithSeed(seed)          // uint64(with seed)
c.Sum64WithSeeds(seed0, seed1) // uint64(with seeds)
c.Sum128()                     // Uint128
c.Sum128WithSeed(seed128)      // Uint128(with seed)

// Sum() call size bits function.(Sum32() or Sum64() or Sum128())
c.Sum(p)    // []byte(buf+p) 
c.Sum(nil)  // []byte(buf)
c.String()  // string(format:%x)

c.Buf()
c.Size()
c.BlockSize()
c.Reset()
```