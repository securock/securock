package sast_test

import (
	"math"
	"testing"

	"github.com/securock/securock/internal/sast"
)

func TestSequenceIndexBounds(t *testing.T) {
	for _, tt := range []struct {
		name     string
		index    int64
		size     int
		negative bool
		want     int
		valid    bool
	}{
		{"first element", 0, 2, false, 0, true},
		{"last tracked element", 63, 64, false, 63, true},
		{"one past end", 2, 2, false, 0, false},
		{"one past tracking limit", 64, 64, false, 0, false},
		{"empty sequence", 0, 0, true, 0, false},
		{"negative empty index", -1, 0, true, 0, false},
		{"python last element", -1, 64, true, 63, true},
		{"python first element", -64, 64, true, 0, true},
		{"python before first", -65, 64, true, 0, false},
		{"java negative index", -1, 2, false, 0, false},
		{"above signed 32 bit", int64(math.MaxInt32) + 1, 2, false, 0, false},
		{"would wrap to zero on 32 bit", 1 << 32, 2, false, 0, false},
		{"maximum signed 64 bit", math.MaxInt64, 64, true, 0, false},
		{"minimum signed 64 bit", math.MinInt64, 64, true, 0, false},
		{"negative size", 0, -1, true, 0, false},
		{"size above tracking limit", 0, 65, false, 0, false},
		{"maximum host size", 0, math.MaxInt, false, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, valid := sast.SequenceIndexForTest(tt.index, tt.size, tt.negative)
			if got != tt.want || valid != tt.valid {
				t.Fatalf("got (%d, %t), want (%d, %t)", got, valid, tt.want, tt.valid)
			}
		})
	}
}
