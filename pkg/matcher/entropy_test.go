package matcher

import (
	"math"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	got := shannonEntropy(nil)
	if got != 0 {
		t.Errorf("expected 0 for nil, got %f", got)
	}
	got = shannonEntropy([]byte{})
	if got != 0 {
		t.Errorf("expected 0 for empty, got %f", got)
	}
}

func TestShannonEntropy_SingleByteRepeated(t *testing.T) {
	// All same byte → entropy 0
	got := shannonEntropy([]byte("aaaaaaa"))
	if got != 0 {
		t.Errorf("expected 0 for repeated single char, got %f", got)
	}
}

func TestShannonEntropy_TwoEqualSymbols(t *testing.T) {
	// "ab" — 2 equally probable symbols → entropy 1.0
	got := shannonEntropy([]byte("ab"))
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("expected 1.0 for 'ab', got %f", got)
	}
}

func TestShannonEntropy_FourEqualSymbols(t *testing.T) {
	// "abcd" — 4 equally probable symbols → entropy 2.0
	got := shannonEntropy([]byte("abcd"))
	if math.Abs(got-2.0) > 1e-9 {
		t.Errorf("expected 2.0 for 'abcd', got %f", got)
	}
}

func TestShannonEntropy_HighEntropy(t *testing.T) {
	// Random-looking 32-byte string — should be well above 3.0
	got := shannonEntropy([]byte("aB3$xY9!mN2@kL7#pQ1%vR4^wS6&zT8*"))
	if got < 3.0 {
		t.Errorf("expected high entropy (>3.0) for mixed chars, got %f", got)
	}
}
