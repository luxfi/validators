// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validators

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// A validator answer carries two ids — a NodeID is [20]byte and a TxID is
// [32]byte — and a DERIVED codec refuses a fixed array outright. zap_gen.go is
// why getValidatorsAt can cross the plane at all; this is that both ids and the
// keys beside them arrive whole.
func TestTheIDsSurviveTheWire(t *testing.T) {
	require := require.New(t)

	sent := GetValidatorOutput{
		NodeID:       ids.NodeID{0: 0xab, 19: 0xcd},
		PublicKey:    []byte{1, 2, 3},
		CoronaPubKey: []byte{4, 5},
		Light:        7,
		Weight:       7,
		TxID:         ids.ID{0: 0xf0, 31: 0x0d},
	}
	enc, err := sent.MarshalZAP()
	require.NoError(err)

	var back GetValidatorOutput
	require.NoError(back.UnmarshalZAP(enc))
	require.Equal(sent, back)
}
