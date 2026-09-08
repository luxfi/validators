// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"github.com/luxfi/ids"
)

// SetRoot is the commitment to a weighted validator set: a SHA-256 over the
// validators sorted by node id, each written as
//
//	nodeID || light(8,BE) || len(pubkey)(8,BE) || pubkey
//
// Sorting by node id and length-prefixing the key make the encoding canonical,
// so two nodes holding the same set compute the same root and a set that
// differs by one bit does not. The empty set commits to ids.Empty, which is
// the "unbound" answer every reader already expects.
//
// This is the one definition of that encoding. A signer and an assembler that
// each carried their own would agree until they didn't.
func SetRoot(set map[ids.NodeID]*GetValidatorOutput) ids.ID {
	if len(set) == 0 {
		return ids.Empty
	}
	nodeIDs := make([]ids.NodeID, 0, len(set))
	for nodeID := range set {
		nodeIDs = append(nodeIDs, nodeID)
	}
	slices.SortFunc(nodeIDs, func(a, b ids.NodeID) int {
		return bytes.Compare(a[:], b[:])
	})
	h := sha256.New()
	var u64 [8]byte
	for _, nodeID := range nodeIDs {
		v := set[nodeID]
		h.Write(nodeID[:])
		binary.BigEndian.PutUint64(u64[:], v.Light)
		h.Write(u64[:])
		binary.BigEndian.PutUint64(u64[:], uint64(len(v.PublicKey)))
		h.Write(u64[:])
		h.Write(v.PublicKey)
	}
	var root ids.ID
	copy(root[:], h.Sum(nil))
	return root
}
