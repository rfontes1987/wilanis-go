// Package harness is the certification harness of CERTIFICATION.md: it
// verifies the manifest freeze, loads and runs golden vectors against the
// §15.9 facade, and drives the property theorems.
package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rfontes1987/wilanis-go/internal/value"
	"github.com/rfontes1987/wilanis-go/internal/wire"
)

// VerifyManifest computes plain SHA-256 over the bytes of every file under
// schemas/, vectors/, properties/ and compares against MANIFEST.json (§15.6).
// It returns the manifest version and the hash of the manifest file's bytes.
func VerifyManifest(confDir string) (version string, manifestHash string, err error) {
	manifestBytes, err := os.ReadFile(filepath.Join(confDir, "MANIFEST.json"))
	if err != nil {
		return "", "", err
	}
	manifestHash = value.HashBytes(manifestBytes)
	mv, err := wire.Parse(manifestBytes)
	if err != nil {
		return "", "", fmt.Errorf("manifest: %w", err)
	}
	m, ok := mv.(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("manifest: not a map")
	}
	version, _ = m["manifestVersion"].(string)
	files, _ := m["files"].(map[string]any)
	if version == "" || files == nil {
		return "", "", fmt.Errorf("manifest: missing fields")
	}
	// every listed file must exist with the recorded hash
	for rel, want := range files {
		b, err := os.ReadFile(filepath.Join(confDir, filepath.FromSlash(rel)))
		if err != nil {
			return "", "", fmt.Errorf("manifest lists %s: %w", rel, err)
		}
		got := value.HashBytes(b)
		if got != want {
			return "", "", fmt.Errorf("hash mismatch for %s", rel)
		}
	}
	// every present file must be listed
	for _, dir := range []string{"schemas", "vectors", "properties"} {
		root := filepath.Join(confDir, dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(confDir, path)
			rel = filepath.ToSlash(rel)
			if _, listed := files[rel]; !listed {
				return fmt.Errorf("unlisted file %s", rel)
			}
			return nil
		})
		if err != nil {
			return "", "", err
		}
	}
	return version, manifestHash, nil
}

// Vector is one loaded golden vector (§15.3): the envelope fields plus the
// whole document as a value.
type Vector struct {
	ID     string
	Family string
	Level  int
	Doc    map[string]any
}

// LoadVectors loads every vector under confDir/vectors.
func LoadVectors(confDir string) ([]*Vector, error) {
	var out []*Vector
	root := filepath.Join(confDir, "vectors")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		v, err := wire.Parse(b)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		doc, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: not a map", path)
		}
		id, _ := doc["id"].(string)
		family, _ := doc["family"].(string)
		level, _ := doc["level"].(int64)
		out = append(out, &Vector{ID: id, Family: family, Level: int(level), Doc: doc})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Seeds is the parsed properties/seeds.json.
type Seeds struct {
	Generator string
	Theorems  map[string][]int64
}

// LoadSeeds loads confDir/properties/seeds.json.
func LoadSeeds(confDir string) (*Seeds, error) {
	b, err := os.ReadFile(filepath.Join(confDir, "properties", "seeds.json"))
	if err != nil {
		return nil, err
	}
	v, err := wire.Parse(b)
	if err != nil {
		return nil, err
	}
	doc := v.(map[string]any)
	s := &Seeds{Generator: doc["generator"].(string), Theorems: map[string][]int64{}}
	for tid, tv := range doc["theorems"].(map[string]any) {
		var list []int64
		for _, sv := range tv.(map[string]any)["seeds"].([]any) {
			list = append(list, sv.(int64))
		}
		s.Theorems[tid] = list
	}
	return s, nil
}

// RunVector runs one vector and returns pass | fail | error.
func RunVector(v *Vector) (outcome string) {
	defer func() {
		if r := recover(); r != nil {
			outcome = "error"
		}
	}()
	switch v.Family {
	case "identity":
		return runIdentity(v)
	case "compile":
		return runCompile(v)
	case "expression":
		return runExpression(v)
	case "execution":
		return runExecution(v)
	case "migration":
		return runMigration(v)
	}
	return "error"
}

// ResolvePointer resolves an RFC 6901 JSON Pointer into a value (Appendix A.3).
func ResolvePointer(v any, pointer string) (any, bool) {
	if pointer == "" {
		return v, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	cur := v
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(tok, "~1", "/")
		tok = strings.ReplaceAll(tok, "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			nv, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = nv
		case []any:
			idx := -1
			if tok != "" && (tok == "0" || tok[0] != '0') {
				n := 0
				valid := true
				for _, ch := range tok {
					if ch < '0' || ch > '9' {
						valid = false
						break
					}
					n = n*10 + int(ch-'0')
				}
				if valid {
					idx = n
				}
			}
			if idx < 0 || idx >= len(c) {
				return nil, false
			}
			cur = c[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func runIdentity(v *Vector) string {
	if rej, ok := v.Doc["reject"].(map[string]any); ok {
		raw := rej["raw"].(string)
		reason := rej["reason"].(string)
		_, err := wire.Parse([]byte(raw))
		if rerr, isReject := err.(*wire.RejectError); isReject && rerr.Reason == reason {
			return "pass"
		}
		// Any refusal counts; the reason token is our own cross-check.
		if err != nil {
			return "fail"
		}
		return "fail"
	}
	val := v.Doc["value"]
	want, _ := v.Doc["hash"].(string)
	if value.Hash(val) != want {
		return "fail"
	}
	if subtrees, ok := v.Doc["subtrees"].(map[string]any); ok {
		for ptr, wantHash := range subtrees {
			sub, ok := ResolvePointer(val, ptr)
			if !ok {
				return "fail"
			}
			if value.Hash(sub) != wantHash.(string) {
				return "fail"
			}
		}
	}
	return "pass"
}
