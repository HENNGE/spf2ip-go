package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeepCopyMap(t *testing.T) {
	t.Parallel()

	originalMap := map[string]struct{}{
		"ori": {},
	}

	shallowCopiedMap := originalMap
	deepCopiedMap := deepCopyMap(originalMap)

	// Modify the original map
	originalMap["new"] = struct{}{}

	assert.NotEqual(t, originalMap, deepCopiedMap, "Deep copy should not point to the same map instance")
	assert.Equal(t, originalMap, shallowCopiedMap, "Shallow copy should point to the same map instance")
}
