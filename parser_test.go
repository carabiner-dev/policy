// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLocalGroups(t *testing.T) {
	t.Parallel()
	t.Run("test-parse-localset-group", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySetFile("testdata/groups-local.json")
		require.NoError(t, err)
		require.NotNil(t, set)

		require.Equal(t, "Simple policy set tp test locally defined policy groups", set.GetMeta().GetDescription())
		require.Len(t, set.GetPolicies(), 0)
		require.Len(t, set.GetGroups(), 1)
		require.Len(t, set.GetGroups()[0].GetBlocks(), 4)
		require.Equal(t, "single-passing", set.GetGroups()[0].GetBlocks()[0].GetId())
		require.Len(t, set.GetGroups()[0].GetBlocks()[1].GetPolicies(), 2)
	})

	t.Run("test-parse-local-group", func(t *testing.T) {
		t.Parallel()
		grp, err := NewParser().ParsePolicyGroupFile("testdata/group.single.json")
		require.NoError(t, err)
		require.NotNil(t, grp)

		require.Equal(t, "Group testing the assert modes", grp.GetMeta().GetDescription())
		require.Len(t, grp.GetBlocks(), 4)
		require.Equal(t, "single-passing", grp.GetBlocks()[0].GetId())
		require.Len(t, grp.GetBlocks()[1].GetPolicies(), 2)
	})

}
