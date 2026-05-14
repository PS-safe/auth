package password

import "testing"

func TestHashThenVerify(t *testing.T) {
	h, err := Hash("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("hunter2", h) {
		t.Error("Verify rejected correct password")
	}
	if Verify("hunter3", h) {
		t.Error("Verify accepted wrong password")
	}
}

func TestEachHashDifferent(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Error("two hashes of the same password are identical; salt is broken")
	}
}

func TestVerifyMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$",
		"$argon2id$v=99$m=1024,t=1,p=1$x$y",
	}
	for _, c := range cases {
		if Verify("anything", c) {
			t.Errorf("Verify accepted malformed hash %q", c)
		}
	}
}

func TestHashEmptyRejected(t *testing.T) {
	if _, err := Hash(""); err == nil {
		t.Error("Hash(\"\") should error")
	}
}
