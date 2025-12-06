// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCompilerPreservesRemoteAssertMode verifies that when compiling a policyset
// with a remote policy reference, the assertMode from the remote policy is preserved
// and not overwritten by default values during parsing.
func TestCompilerPreservesRemoteAssertMode(t *testing.T) {
	t.Parallel()

	// Create a remote policy with assertMode "OR"
	remotePolicyJSON := []byte(`{
		"id": "remote-policy",
		"meta": {
			"description": "Remote policy with OR mode",
			"assertMode": "OR"
		},
		"tenets": [{
			"id": "tenet1",
			"code": "true"
		}]
	}`)

	// Create a policyset JSON that references the remote policy
	policySetJSON := []byte(`{
		"id": "test-set",
		"meta": {
			"description": "Test policyset"
		},
		"policies": [{
			"source": {
				"location": {
					"uri": "https://example.com/remote-policy.json"
				}
			}
		}]
	}`)

	// Parse the policyset (this is where defaults get applied)
	parser := NewParser()
	policySet, _, err := parser.ParseVerifyPolicySet(policySetJSON)
	require.NoError(t, err)
	require.NotNil(t, policySet)

	// Create a mock storage backend that returns our remote policy
	store := newRefStore()
	ref := policySet.Policies[0].Source
	ref.Location.Content = remotePolicyJSON
	_, _, _, err = store.StoreReferenceWithReturn(ref)
	require.NoError(t, err)

	// Compile the policyset
	compiler := &Compiler{
		Options: defaultCompilerOpts,
		Store:   store,
		impl:    &defaultCompilerImpl{},
	}

	compiledSet, err := compiler.CompileSet(policySet)
	require.NoError(t, err)
	require.NotNil(t, compiledSet)
	require.Len(t, compiledSet.Policies, 1)

	// Verify that the assertMode "OR" from the remote policy was preserved
	compiledPolicy := compiledSet.Policies[0]
	require.NotNil(t, compiledPolicy.Meta)
	require.Equal(t, "OR", compiledPolicy.Meta.AssertMode, "assertMode should be preserved from remote policy")
	require.Equal(t, "remote-policy", compiledPolicy.Id)
	require.Nil(t, compiledPolicy.Source, "source should be cleared after assembly")
}

/*

test case:
The following reference needs to fail in a policy
if the source URI points to a policy set. If json-file.json
is a policy, then it should work fine.

{
    "source": {
        "location": {
            "uri": "git+https://github.com/example/repo@9834934873487978349789#json-file.json"
        }
    }
},



TEST CASE:

Pulling this reference needs to fail (the hash is not right):

{
            "location": {
                "uri": "git+https://github.com/puerco/lab#ampel/minimum-elements.policy.json@0f99ab885ebe8d37e1b8d9c6a0708339fd686402",
                "digest": {
                    "sha256": "ba069d6f37afff1aafa0b483949f7d05a4137cba50406875055d222fa138e99c"
                }
            }
        }

*/

// PolicyGroup Commpiling Tests
func TestCompileLocalGroups(t *testing.T) {
	t.Parallel()
	t.Run("test-localset-group", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySetFile("testdata/groups-local.json")
		require.NoError(t, err)
		require.NotNil(t, set)

		set, err = NewCompiler().CompileSet(set)
		require.NoError(t, err)

		require.Equal(t, "Simple policy set tp test locally defined policy groups", set.GetMeta().GetDescription())
		require.Len(t, set.GetPolicies(), 0)
		require.Len(t, set.GetGroups(), 1)
		require.Len(t, set.GetGroups()[0].GetBlocks(), 4)
		require.Equal(t, "single-passing", set.GetGroups()[0].GetBlocks()[0].GetId())
		require.Len(t, set.GetGroups()[0].GetBlocks()[1].GetPolicies(), 2)
	})

	t.Run("test-local-group", func(t *testing.T) {
		t.Parallel()
		grp, err := NewParser().ParsePolicyGroupFile("testdata/group.single.json")
		require.NoError(t, err)
		require.NotNil(t, grp)

		grp, err = NewCompiler().CompilePolicyGroup(grp)
		require.NoError(t, err)

		require.Equal(t, "Group testing the assert modes", grp.GetMeta().GetDescription())
		require.Len(t, grp.GetBlocks(), 4)
		require.Equal(t, "single-passing", grp.GetBlocks()[0].GetId())
		require.Len(t, grp.GetBlocks()[1].GetPolicies(), 2)
	})

	t.Run("test-remote-group", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySetFile("testdata/group.remoteref.json")
		require.NoError(t, err)
		require.NotNil(t, set)

		set, err = NewCompiler().CompileSet(set)
		require.NoError(t, err)

		require.Equal(t, "Policy set testing remote referenced group", set.GetMeta().GetDescription())
		require.Len(t, set.GetPolicies(), 0)
		require.Len(t, set.GetGroups(), 1)
		require.Equal(t, "Group testing the assert modes", set.GetGroups()[0].GetMeta().GetDescription())
		require.Len(t, set.GetGroups()[0].GetBlocks(), 4)
		require.Equal(t, "single-passing", set.GetGroups()[0].GetBlocks()[0].GetId())
		require.Len(t, set.GetGroups()[0].GetBlocks()[1].GetPolicies(), 2)
	})
}
