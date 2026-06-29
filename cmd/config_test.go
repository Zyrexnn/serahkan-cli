package cmd

import "testing"

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "(empty)"},
		{name: "short", input: "abcd", want: "****"},
		{name: "long", input: "abcdefgh", want: "ab****gh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskSecret(tt.input); got != tt.want {
				t.Fatalf("maskSecret(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseNonNegativeInt(t *testing.T) {
	value, err := parseNonNegativeInt("3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != 3 {
		t.Fatalf("expected 3, got %d", value)
	}

	if _, err := parseNonNegativeInt("-1"); err == nil {
		t.Fatalf("expected error for negative value")
	}

	if _, err := parseNonNegativeInt("abc"); err == nil {
		t.Fatalf("expected error for non-integer value")
	}
}
