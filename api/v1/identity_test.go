// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		mustFail bool
		sut      *Identity
	}{
		{"sigstore", false, &Identity{
			Id: "sut",
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "test@example.com",
			},
		}},
		{"key", false, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"ref", false, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
		}},
		{"no-ids", true, &Identity{}},
		{"two-ids", true, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"key-no-data-or-id", true, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id: "", Type: "rsa", Data: "",
			},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.sut.Validate()
			if tt.mustFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
