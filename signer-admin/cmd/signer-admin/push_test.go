package main

import (
	"encoding/json"
	"testing"
)

// A delayed -raise-min for an older version must not lower the floor that
// another command saved after this one read cloud.json.
func TestRaiseFloorKeepsHigher(t *testing.T) {
	const key = "min_locked_version"
	att := map[string]json.RawMessage{key: json.RawMessage("2")}
	raised, err := raiseFloor(att, key, 1)
	if err != nil || raised || string(att[key]) != "2" {
		t.Fatalf("raise to 1 over 2: raised %v, err %v, floor %s", raised, err, att[key])
	}
	raised, err = raiseFloor(att, key, 3)
	if err != nil || !raised || string(att[key]) != "3" {
		t.Fatalf("raise to 3 over 2: raised %v, err %v, floor %s", raised, err, att[key])
	}
	att = map[string]json.RawMessage{}
	if raised, err = raiseFloor(att, key, 1); err != nil || !raised || string(att[key]) != "1" {
		t.Fatalf("raise to 1, no floor: raised %v, err %v, floor %s", raised, err, att[key])
	}
}
