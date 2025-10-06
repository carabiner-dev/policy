// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextValValidate(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		sut     *ContextVal
		mustErr bool
	}{
		{"no-value", &ContextVal{Type: ""}, false},
		{"no-value", &ContextVal{Type: "string"}, false},
		{"no-value", &ContextVal{Type: "int"}, false},
		{"no-value", &ContextVal{Type: "bool"}, false},
		{"no-value", &ContextVal{Type: "something-else"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.sut.Validate()
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
