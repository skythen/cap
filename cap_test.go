package cap

import (
	"archive/zip"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		capFilename string
		expectError bool
	}{
		{
			name:        "parsing CAP without header component is expected to fail",
			capFilename: "./test-files/no-header.cap",
			expectError: true,
		},
		{
			name:        "parsing CAP with invalid 0 component is expected to fail",
			capFilename: "./test-files/invalid-0-component.cap",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zf, err := zip.OpenReader(tc.capFilename)
			if err != nil {
				t.Fatalf("unable to open cap file %s: %s", tc.capFilename, err)
			}

			if zf != nil {
				defer zf.Close()
			}

			_, err = Parse(&zf.Reader)
			if tc.expectError != (err != nil) {
				t.Fatalf("error expected: %t, actual: %t, err: %s", tc.expectError, err != nil, err)
			}

		})
	}
}
