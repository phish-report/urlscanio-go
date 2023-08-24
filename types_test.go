package urlscanio

import (
	"encoding/json"
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
			n := Nullable[string]{}
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
