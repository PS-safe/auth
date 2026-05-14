package session

import "testing"

func TestGenerateUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 1000 {
		tok, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[tok]; dup {
			t.Errorf("duplicate token %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestHashDeterministic(t *testing.T) {
	if Hash("abc") != Hash("abc") {
		t.Error("Hash is non-deterministic")
	}
	if Hash("abc") == Hash("abd") {
		t.Error("Hash collides between distinct inputs")
	}
}
