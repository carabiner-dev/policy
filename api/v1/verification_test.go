// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchesKeyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		matches bool
		sut     *SignatureVerification
		id      *IdentityKey
	}{
		{
			"single-id", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "1234abc", Data: ""},
		},
		{
			"single-data", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "", Data: "keydata"},
		},
		{
			"single-both", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "1234abc", Data: "keydata"},
		},
		{
			"miss-id-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "wrong", Data: "keydata"},
		},
		{
			"miss-data-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "1234abc", Data: "wrong"},
		},
		{
			"two-keys-one-match", false,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}},
					{Key: &IdentityKey{Id: "5678def", Data: "other-keydata"}},
				},
			}, &IdentityKey{Id: "1234abc", Data: "wrong"},
		},
		{
			"two-keys-two-matches", false,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Data: ""}},
					{Key: &IdentityKey{Id: "1234abc", Data: ""}},
				},
			}, &IdentityKey{Id: "1234abc", Data: "wrong"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sut.MatchesKeyIdentity(tt.id))
		})
	}
}
