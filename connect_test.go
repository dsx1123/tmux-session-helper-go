package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) (string, *sql.DB) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS profile (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(250),
		address VARCHAR(250),
		protocol VARCHAR(16),
		port INTEGER,
		username VARCHAR(250),
		password VARCHAR(250)
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	return dbPath, db
}

func setupTestEncrypt(t *testing.T) *Encrypt {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	err := os.WriteFile(keyFile, []byte("testpassword123"), 0600)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	enc, err := NewEncrypt(keyFile)
	if err != nil {
		t.Fatalf("Failed to create Encrypt: %v", err)
	}

	return enc
}

// Test Encrypt struct
func TestNewEncrypt(t *testing.T) {
	t.Run("with existing key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "test_key")

		err := os.WriteFile(keyFile, []byte("testpassword"), 0600)
		if err != nil {
			t.Fatalf("Failed to create key file: %v", err)
		}

		enc, err := NewEncrypt(keyFile)
		if err != nil {
			t.Errorf("NewEncrypt failed: %v", err)
		}
		if enc == nil {
			t.Error("Expected non-nil Encrypt")
		}
		if len(enc.key) != 32 {
			t.Errorf("Expected key length 32, got %d", len(enc.key))
		}
	})

	t.Run("with non-existent key file", func(t *testing.T) {
		// This test would require stdin interaction, so we skip it
		// In real scenarios, this would need mocking stdin
		t.Skip("Skipping interactive test")
	})
}

func TestEncrypt_Encrypt(t *testing.T) {
	enc := setupTestEncrypt(t)

	tests := []struct {
		name    string
		message string
		wantErr bool
	}{
		{
			name:    "normal message",
			message: "password123",
			wantErr: false,
		},
		{
			name:    "empty message",
			message: "",
			wantErr: false,
		},
		{
			name:    "special characters",
			message: "p@ssw0rd!#$%",
			wantErr: false,
		},
		{
			name:    "long message",
			message: "this is a very long password with many characters 1234567890",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := enc.Encrypt(tt.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.message == "" && encrypted != "" {
				t.Error("Expected empty encrypted string for empty input")
			}
			if tt.message != "" && encrypted == "" {
				t.Error("Expected non-empty encrypted string for non-empty input")
			}
		})
	}
}

func TestEncrypt_Decrypt(t *testing.T) {
	enc := setupTestEncrypt(t)

	tests := []struct {
		name     string
		message  string
		wantErr  bool
	}{
		{
			name:    "normal message",
			message: "password123",
			wantErr: false,
		},
		{
			name:    "empty message",
			message: "",
			wantErr: false,
		},
		{
			name:    "special characters",
			message: "p@ssw0rd!#$%",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := enc.Encrypt(tt.message)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := enc.Decrypt(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if decrypted != tt.message {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.message)
			}
		})
	}
}

func TestEncrypt_DecryptInvalidData(t *testing.T) {
	enc := setupTestEncrypt(t)

	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "invalid base64",
			data:    "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "empty string",
			data:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test Connection struct
func TestNewConnection(t *testing.T) {
	enc := setupTestEncrypt(t)
	dbPath, db := setupTestDB(t)
	defer db.Close()

	conn, err := NewConnection(enc, dbPath, "test-session")
	if err != nil {
		t.Fatalf("NewConnection failed: %v", err)
	}
	defer conn.Close()

	if conn.db == nil {
		t.Error("Expected non-nil database connection")
	}
	if conn.enc == nil {
		t.Error("Expected non-nil encryption")
	}
	if conn.tmuxSession != "test-session" {
		t.Errorf("Expected tmuxSession 'test-session', got %s", conn.tmuxSession)
	}
}

func TestConnection_ListProfileNames(t *testing.T) {
	enc := setupTestEncrypt(t)
	dbPath, db := setupTestDB(t)
	defer db.Close()

	// Insert test data
	_, err := db.Exec("INSERT INTO profile (name, address, protocol, port, username, password) VALUES (?, ?, ?, ?, ?, ?)",
		"test1", "192.168.1.1", "ssh", 22, "admin", "")
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	_, err = db.Exec("INSERT INTO profile (name, address, protocol, port, username, password) VALUES (?, ?, ?, ?, ?, ?)",
		"test2", "192.168.1.2", "ssh", 22, "admin", "")
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	conn, _ := NewConnection(enc, dbPath, "test-session")
	defer conn.Close()

	names, err := conn.ListProfileNames()
	if err != nil {
		t.Fatalf("ListProfileNames failed: %v", err)
	}

	if len(names) != 2 {
		t.Errorf("Expected 2 profile names, got %d", len(names))
	}

	if names[0] != "test1" || names[1] != "test2" {
		t.Errorf("Expected names [test1, test2], got %v", names)
	}
}

func TestConnection_Profiles(t *testing.T) {
	enc := setupTestEncrypt(t)
	dbPath, db := setupTestDB(t)
	defer db.Close()

	// Insert test data
	_, err := db.Exec("INSERT INTO profile (name, address, protocol, port, username, password) VALUES (?, ?, ?, ?, ?, ?)",
		"test1", "192.168.1.1", "ssh", 22, "admin", "encrypted_pwd")
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	conn, _ := NewConnection(enc, dbPath, "test-session")
	defer conn.Close()

	profiles, err := conn.Profiles()
	if err != nil {
		t.Fatalf("Profiles failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Errorf("Expected 1 profile, got %d", len(profiles))
	}

	p := profiles[0]
	if p.Name != "test1" {
		t.Errorf("Expected name 'test1', got %s", p.Name)
	}
	if p.Address != "192.168.1.1" {
		t.Errorf("Expected address '192.168.1.1', got %s", p.Address)
	}
	if p.Protocol != "ssh" {
		t.Errorf("Expected protocol 'ssh', got %s", p.Protocol)
	}
	if p.Port != 22 {
		t.Errorf("Expected port 22, got %d", p.Port)
	}
	if p.Username != "admin" {
		t.Errorf("Expected username 'admin', got %s", p.Username)
	}
}

func TestConnection_ParseSelection(t *testing.T) {
	enc := setupTestEncrypt(t)
	dbPath, db := setupTestDB(t)
	defer db.Close()

	conn, _ := NewConnection(enc, dbPath, "test-session")
	defer conn.Close()

	tests := []struct {
		name      string
		selection string
		want      []int
	}{
		{
			name:      "single number",
			selection: "1",
			want:      []int{1},
		},
		{
			name:      "multiple numbers",
			selection: "1,3,5",
			want:      []int{1, 3, 5},
		},
		{
			name:      "range",
			selection: "1-5",
			want:      []int{1, 2, 3, 4, 5},
		},
		{
			name:      "mixed range and numbers",
			selection: "1,3-5,7",
			want:      []int{1, 3, 4, 5, 7},
		},
		{
			name:      "duplicates removed",
			selection: "1,1,2,2,3",
			want:      []int{1, 2, 3},
		},
		{
			name:      "with spaces",
			selection: "1, 3, 5",
			want:      []int{1, 3, 5},
		},
		{
			name:      "empty selection",
			selection: "",
			want:      []int{},
		},
		{
			name:      "range with duplicates",
			selection: "1-3,2-4",
			want:      []int{1, 2, 3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := conn.ParseSelection(tt.selection)
			if len(got) != len(tt.want) {
				t.Errorf("ParseSelection() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseSelection() = %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestInitDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_init.db")

	err := initDatabase(dbPath)
	if err != nil {
		t.Fatalf("initDatabase failed: %v", err)
	}

	// Verify table was created
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='profile'").Scan(&tableName)
	if err != nil {
		t.Fatalf("Failed to query table: %v", err)
	}

	if tableName != "profile" {
		t.Errorf("Expected table name 'profile', got %s", tableName)
	}
}

func TestCheckTmuxSession(t *testing.T) {
	// This test depends on tmux being installed and having sessions
	// We'll test the function behavior without actual tmux dependency
	t.Run("non-existent session", func(t *testing.T) {
		result := checkTmuxSession("non-existent-session-12345")
		if result {
			t.Error("Expected false for non-existent session")
		}
	})
}

func TestGenerateCompletions(t *testing.T) {
	// Skip this test as it requires stdout capture
	// In production, this could be tested with output redirection
	t.Skip("Skipping test that requires stdout capture")
}

// Test Profile struct
func TestProfile(t *testing.T) {
	p := Profile{
		ID:       1,
		Name:     "test-server",
		Address:  "192.168.1.100",
		Protocol: "ssh",
		Port:     22,
		Username: "admin",
		Password: "encrypted_password",
	}

	if p.ID != 1 {
		t.Errorf("Expected ID 1, got %d", p.ID)
	}
	if p.Name != "test-server" {
		t.Errorf("Expected Name 'test-server', got %s", p.Name)
	}
	if p.Address != "192.168.1.100" {
		t.Errorf("Expected Address '192.168.1.100', got %s", p.Address)
	}
	if p.Protocol != "ssh" {
		t.Errorf("Expected Protocol 'ssh', got %s", p.Protocol)
	}
	if p.Port != 22 {
		t.Errorf("Expected Port 22, got %d", p.Port)
	}
	if p.Username != "admin" {
		t.Errorf("Expected Username 'admin', got %s", p.Username)
	}
}

// Benchmark tests
func BenchmarkEncrypt(b *testing.B) {
	tmpDir := b.TempDir()
	keyFile := filepath.Join(tmpDir, "bench_key")
	os.WriteFile(keyFile, []byte("testpassword"), 0600)
	enc, _ := NewEncrypt(keyFile)

	message := "this is a test password for benchmarking"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.Encrypt(message)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	tmpDir := b.TempDir()
	keyFile := filepath.Join(tmpDir, "bench_key")
	os.WriteFile(keyFile, []byte("testpassword"), 0600)
	enc, _ := NewEncrypt(keyFile)

	message := "this is a test password for benchmarking"
	encrypted, _ := enc.Encrypt(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.Decrypt(encrypted)
	}
}

func BenchmarkParseSelection(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	keyFile := filepath.Join(tmpDir, "bench_key")
	os.WriteFile(keyFile, []byte("testpassword"), 0600)

	enc, _ := NewEncrypt(keyFile)
	initDatabase(dbPath)
	conn, _ := NewConnection(enc, dbPath, "test-session")
	defer conn.Close()

	selection := "1,3-10,15,20-25,30"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.ParseSelection(selection)
	}
}
