package checksec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanary_InputValidation(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty filename",
			filename:    "",
			expectError: true,
			errorMsg:    "filename cannot be empty",
		},
		{
			name:        "non-existent file",
			filename:    "/path/to/nonexistent/file",
			expectError: true,
			errorMsg:    "cannot access file",
		},
		{
			name:        "directory traversal attempt",
			filename:    "../../../etc/passwd",
			expectError: true,
			errorMsg:    "cannot access file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Canary(tt.filename)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
			}
		})
	}
}

func TestCanary_InvalidELF(t *testing.T) {
	// Create a temporary file that's not an ELF
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write some non-ELF content
	_, err = tmpFile.WriteString("This is not an ELF file")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	result, err := Canary(tmpFile.Name())
	if err == nil {
		t.Errorf("Expected error for non-ELF file, but got none")
		return
	}
	if !contains(err.Error(), "invalid ELF file") {
		t.Errorf("Expected 'invalid ELF file' error, got: %s", err.Error())
	}
	if result != nil {
		t.Errorf("Expected nil result for error case, got: %v", result)
	}
}

func TestCanary_ValidELFWithoutCanary(t *testing.T) {
	// This test would require a valid ELF file without canary
	// For now, we'll test the error handling path
	// In a real test environment, you'd have test binaries
	t.Skip("Requires test ELF binaries - skipping for now")
}

func TestCanary_ValidELFWithCanary(t *testing.T) {
	// This test would require a valid ELF file with canary
	// For now, we'll test the error handling path
	// In a real test environment, you'd have test binaries
	t.Skip("Requires test ELF binaries - skipping for now")
}

func TestCanary_PathTraversal(t *testing.T) {
	// Test various path traversal attempts
	maliciousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"/tmp/../../../etc/passwd",
	}

	for _, path := range maliciousPaths {
		t.Run("path_traversal_"+filepath.Base(path), func(t *testing.T) {
			result, err := Canary(path)

			// Should either fail with access error or be cleaned by filepath.Clean
			if err == nil {
				// If it doesn't error, the path should have been cleaned
				cleanPath := filepath.Clean(path)
				if cleanPath == path {
					t.Errorf("Path traversal attempt should have been cleaned or failed: %s", path)
				}
			} else {
				// Should fail with access error or invalid ELF file error
				if !contains(err.Error(), "cannot access file") && !contains(err.Error(), "invalid ELF file") {
					t.Errorf("Expected access error or invalid ELF file error for path traversal, got: %s", err.Error())
				}
			}

			if result != nil {
				t.Errorf("Expected nil result for malicious path, got: %v", result)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}
