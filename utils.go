package main

import (
	"maps"
)

// Helper to copy a map, as maps are reference types.
func deepCopyMap(originalMap map[string]struct{}) map[string]struct{} {
	if originalMap == nil {
		return nil
	}

	newMap := make(map[string]struct{}, len(originalMap))

	maps.Copy(newMap, originalMap)

	return newMap
}
