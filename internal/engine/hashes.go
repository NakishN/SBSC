package engine

import (
	"encoding/json"
	"fmt"
	"io/fs"
)

type KnownHash struct {
	SHA256   string `json:"sha256"`
	Name     string `json:"name"`
	Category string `json:"category"` // cheat | clean
	Comment  string `json:"comment"`
}

type HashDB struct {
	bySum map[string]*KnownHash
}

func LoadHashes(fsys fs.FS) (*HashDB, error) {
	b, err := fs.ReadFile(fsys, "rules/hashes.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Hashes []*KnownHash `json:"hashes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("hashes.json: %w", err)
	}
	db := &HashDB{bySum: make(map[string]*KnownHash)}
	for _, h := range doc.Hashes {
		if h != nil && len(h.SHA256) == 64 {
			db.bySum[h.SHA256] = h
		}
	}
	return db, nil
}

func (db *HashDB) Lookup(sum string) *KnownHash {
	if db == nil {
		return nil
	}
	return db.bySum[sum]
}
