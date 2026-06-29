package doctor

import "testing"

func TestDeriveModelsURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "http://127.0.0.1:1234/v1/chat/completions",
			want:  "http://127.0.0.1:1234/v1/models",
		},
		{
			input: "http://127.0.0.1:1234/v1/completions",
			want:  "http://127.0.0.1:1234/v1/models",
		},
		{
			input: "http://127.0.0.1:1234/v1",
			want:  "http://127.0.0.1:1234/v1/models",
		},
	}

	for _, tt := range tests {
		if got := deriveModelsURL(tt.input); got != tt.want {
			t.Fatalf("deriveModelsURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
