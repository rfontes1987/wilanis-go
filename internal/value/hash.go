package value

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
)

// Hash computes the structural hash of §6, returned as bare hex.
func Hash(v any) string {
	d := digest(v)
	return hex.EncodeToString(d[:])
}

// HashBytes computes plain SHA-256 over raw bytes (§6.5), bare hex.
func HashBytes(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func digest(v any) [32]byte {
	return sha256.Sum256(caseEncoding(v))
}

// caseEncoding builds the byte string of §6.2.
func caseEncoding(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0x00}
	case bool:
		if x {
			return []byte{0x02}
		}
		return []byte{0x01}
	case int64:
		var sign byte
		var mag uint64
		if x < 0 {
			sign = 0x01
			mag = uint64(-x)
		} else {
			sign = 0x00
			mag = uint64(x)
		}
		// big-endian magnitude with no leading zero bytes (empty for 0)
		var magBytes []byte
		if mag != 0 {
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], mag)
			i := 0
			for i < 8 && buf[i] == 0 {
				i++
			}
			magBytes = buf[i:]
		}
		out := make([]byte, 0, 2+8+len(magBytes))
		out = append(out, 0x03, sign)
		out = appendU64(out, uint64(len(magBytes)))
		out = append(out, magBytes...)
		return out
	case float64:
		f := x
		if f == 0 {
			f = 0 // −0 replaced by +0 (defense in depth; unification makes zero an integer)
		}
		out := make([]byte, 0, 9)
		out = append(out, 0x04)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(f))
		return append(out, buf[:]...)
	case string:
		b := []byte(x)
		out := make([]byte, 0, 9+len(b))
		out = append(out, 0x05)
		out = appendU64(out, uint64(len(b)))
		return append(out, b...)
	case []any:
		out := make([]byte, 0, 9+32*len(x))
		out = append(out, 0x06)
		out = appendU64(out, uint64(len(x)))
		for _, e := range x {
			d := digest(e)
			out = append(out, d[:]...)
		}
		return out
	case map[string]any:
		keys := SortedKeys(x)
		out := make([]byte, 0, 9+64*len(keys))
		out = append(out, 0x07)
		out = appendU64(out, uint64(len(keys)))
		for _, k := range keys {
			kd := digest(k)
			vd := digest(x[k])
			out = append(out, kd[:]...)
			out = append(out, vd[:]...)
		}
		return out
	}
	panic("value: not a model value")
}

func appendU64(out []byte, n uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	return append(out, buf[:]...)
}
