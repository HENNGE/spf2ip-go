package spf2ip

import (
	"maps"
)

// deepCopyMap is a helper for copying a map, as maps are reference types.
func deepCopyMap(originalMap map[string]struct{}) map[string]struct{} {
	if originalMap == nil {
		return nil
	}

	newMap := make(map[string]struct{}, len(originalMap))

	maps.Copy(newMap, originalMap)

	return newMap
}
