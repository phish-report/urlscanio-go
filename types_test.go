package urlscanio

import (
	"context"
	"encoding/json"
	"github.com/bradleyjkemp/cupaloy/v2"
	"testing"
)

func TestNullable_UnmarshalJSON(t *testing.T) {
	type testCase struct {
		input string
		want  []string
	}
	tests := []testCase{
		{"{}", nil},
		{"[]", []string{}},
		{"[\"foo\"]", []string{"foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			n := NullableSlice[string]{}
			if err := json.Unmarshal([]byte(tt.input), &n); err != nil {
				t.Fatal(err)
			}
			if len(n) != len(tt.want) {
				t.Fatal("wrong number of elements")
			}

			for i := range n {
				if n[i] != tt.want[i] {
					t.Errorf("mismatch in index %d: wanted %s, got %s", i, n[i], tt.want[i])
				}
			}
		})
	}
}

func TestSnapshot(t *testing.T) {
	tc := []string{
		"663bc207-f1fd-4f41-b413-3cc99f1e31b8",
	}

	for _, uuid := range tc {
		t.Run(uuid, func(t *testing.T) {
			r, err := NewClient().RetrieveResult(context.Background(), uuid)
			if err != nil {
				t.Fatal(err)
			}

			cupaloy.SnapshotT(t, r)
		})
	}
}
