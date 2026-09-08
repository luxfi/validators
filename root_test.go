// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/luxfi/ids"
)

// TestSetRoot pins the set-root encoding. A change here is consensus-breaking:
// every node computes this root over the same set and signs against it, so two
// encodings are two networks.
func TestSetRoot(t *testing.T) {
	var a, b ids.NodeID
	a[0], b[0] = 0x01, 0x02
	set := map[ids.NodeID]*GetValidatorOutput{
		b: {NodeID: b, PublicKey: []byte{0xcc}, Light: 20},
		a: {NodeID: a, PublicKey: []byte{0xaa, 0xbb}, Light: 10},
	}

	// Recomputed from the spec rather than from SetRoot, so this is a check and
	// not a tautology.
	h := sha256.New()
	var u64 [8]byte
	for _, v := range []struct {
		id    ids.NodeID
		pk    []byte
		light uint64
	}{{a, []byte{0xaa, 0xbb}, 10}, {b, []byte{0xcc}, 20}} {
		h.Write(v.id[:])
		binary.BigEndian.PutUint64(u64[:], v.light)
		h.Write(u64[:])
		binary.BigEndian.PutUint64(u64[:], uint64(len(v.pk)))
		h.Write(u64[:])
		h.Write(v.pk)
	}
	var want ids.ID
	copy(want[:], h.Sum(nil))

	if got := SetRoot(set); got != want {
		t.Fatalf("set-root encoding drifted:\n got  %s\n want %s", got, want)
	}
	if SetRoot(nil) != ids.Empty {
		t.Fatal("nil set commits to ids.Empty")
	}
	if SetRoot(map[ids.NodeID]*GetValidatorOutput{}) != ids.Empty {
		t.Fatal("empty set commits to ids.Empty")
	}
}
