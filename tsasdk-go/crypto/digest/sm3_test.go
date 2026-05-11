package digest

import (
	"encoding/hex"
	"testing"
)

const sm3ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

func TestSM3KnownVector(t *testing.T) {
	got := SM3.FromString("abc")
	want := Digest("sm3:" + sm3ABC)
	if got != want {
		t.Fatalf("SM3.FromString mismatch: got %s want %s", got, want)
	}
}

func TestComputeHashByAlgorithmSM3(t *testing.T) {
	sum, err := ComputeHashByAlgorithm(SM3, []byte("abc"))
	if err != nil {
		t.Fatalf("ComputeHashByAlgorithm returned error: %v", err)
	}
	if got := hex.EncodeToString(sum); got != sm3ABC {
		t.Fatalf("SM3 hash mismatch: got %s want %s", got, sm3ABC)
	}
}
