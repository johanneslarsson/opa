package topdown

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

type hashFunction func(a ast.Value) (ast.Value, error)
type hashTest struct {
	note     string
	input    string
	expected string
}

func TestHashMd5SumHexEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "md5 hex test",
			input:    "lorem ipsum",
			expected: "80a751fde577028640c419000e33eba6",
		},
	}
	evalTest(t, tests, builtinCryptoMd5)
}

func TestHashMd5SumBase64UrlEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "md5 base64 url test",
			input:    "lorem ipsum",
			expected: "gKdR_eV3AoZAxBkADjPrpg",
		},
	}
	evalTest(t, tests, builtinCryptoMd5Base64UrlEncode)
}

func TestHashSha1SumHexEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "sha1 hex test",
			input:    "lorem ipsum",
			expected: "bfb7759a67daeb65410490b4d98bb9da7d1ea2ce",
		},
	}
	evalTest(t, tests, builtinCryptoSha1)
}

func TestHashSha1SumBase64UrlEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "sha1 base64 url test",
			input:    "lorem ipsum",
			expected: "v7d1mmfa62VBBJC02Yu52n0eos4",
		},
	}
	evalTest(t, tests, builtinCryptoSha1Base64UrlEncode)
}

func TestHashSha256SumHexEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "sha256 hex test",
			input:    "lorem ipsum",
			expected: "5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269",
		},
	}
	evalTest(t, tests, builtinCryptoSha256)
}

func TestHashSha256Base64UrlEncode(t *testing.T) {
	tests := []hashTest{
		{
			note:     "sha256 base64 url test",
			input:    "lorem ipsum",
			expected: "Xiv1fT9AxLbfadrxk2y3ZvgyN0tPwCWafL_wbi9w8mk",
		},
	}
	evalTest(t, tests, builtinCryptoSha256Base64UrlEncode)
}

func evalTest(t *testing.T, tests []hashTest, hash hashFunction) {
	for i, tc := range tests {
		t.Run(tc.note, func(t *testing.T) {
			actual, err := hash(ast.String(tc.input))
			if err != nil {
				t.Fatalf("%v (#%d): Err from hash function with input to equal %v",
					tc.note, i+1, tc.input)
			}
			expected := ast.String(tc.expected)
			if actual.Compare(expected) != 0 {
				t.Fatalf("%v (#%d): Expected input to equal %v but got: %v", tc.note, i+1, expected, actual)
			}
		})
	}
}
