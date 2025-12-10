package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	author           = "shangxindu@gmail.com"
	tmuxSession      = "default"
	tmuxFloaxSession = "floax"
)

type Profile struct {
	ID       int
	Name     string
	Address  string
	Protocol string
	Port     int
	Username string
	Password string
}

type Encrypt struct {
	key []byte
}

func NewEncrypt(keyFile string) (*Encrypt, error) {
	var password string

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		fmt.Printf("encryption file %s doesn't exist, creating one?[y/n]: ", keyFile)
		reader := bufio.NewReader(os.Stdin)
		creating, _ := reader.ReadString('\n')
		creating = strings.TrimSpace(strings.ToLower(creating))

		if creating == "y" {
			fmt.Print("encryption password: ")
			password, _ = reader.ReadString('\n')
			password = strings.TrimSpace(password)
			if err := os.WriteFile(keyFile, []byte(password), 0600); err != nil {
				return nil, err
			}
		} else {
			os.Exit(0)
		}
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	password = string(data)

	key := pbkdf2.Key([]byte(password), []byte(""), 10000, 32, sha256.New)
	encodedKey := base64.URLEncoding.EncodeToString(key)

	return &Encrypt{key: []byte(encodedKey)[:32]}, nil
}

func (e *Encrypt) Encrypt(message string) (string, error) {
	if message == "" {
		return "", nil
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(message))
	result := make([]byte, len(encoded))
	for i := 0; i < len(encoded); i++ {
		result[i] = encoded[i] ^ e.key[i%len(e.key)]
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

func (e *Encrypt) Decrypt(message string) (string, error) {
	if message == "" {
		return "", nil
	}
	decoded, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	result := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ e.key[i%len(e.key)]
	}
	plaintext, err := base64.StdEncoding.DecodeString(string(result))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

type Connection struct {
	db          *sql.DB
	enc         *Encrypt
	profile     []Profile
	tmuxSession string
}

func NewConnection(enc *Encrypt, dbPath string, tmuxSession string) (*Connection, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	return &Connection{
		db:          db,
		enc:         enc,
		profile:     []Profile{},
		tmuxSession: tmuxSession,
	}, nil
}

func (c *Connection) Close() {
	c.db.Close()
}

func (c *Connection) Connect(name string) {
	profiles := c.GetSelected(name)
	if len(profiles) > 0 {
		for _, p := range profiles {
			c.ReleaseToTmux(p)
		}
	} else {
		os.Exit(1)
	}
}

func (c *Connection) ListProfileNames() ([]string, error) {
	rows, err := c.db.Query("SELECT name FROM profile ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func (c *Connection) Profiles() ([]Profile, error) {
	rows, err := c.db.Query("SELECT id, name, address, protocol, port, username, password FROM profile ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []Profile
	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.Address, &p.Protocol, &p.Port, &p.Username, &p.Password); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func (c *Connection) ParseSelection(selection string) []int {
	result := []int{}
	temp := strings.Split(selection, ",")

	expand := func(sec string) []int {
		stripped := strings.TrimSpace(sec)
		if stripped == "" {
			return []int{}
		}

		if !strings.Contains(stripped, "-") {
			num, _ := strconv.Atoi(stripped)
			return []int{num}
		}

		parts := strings.Split(stripped, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		expanded := []int{}
		for i := start; i <= end; i++ {
			expanded = append(expanded, i)
		}
		return expanded
	}

	for _, sec := range temp {
		result = append(result, expand(sec)...)
	}

	uniqueMap := make(map[int]bool)
	unique := []int{}
	for _, v := range result {
		if !uniqueMap[v] {
			uniqueMap[v] = true
			unique = append(unique, v)
		}
	}
	sort.Ints(unique)
	return unique
}

func (c *Connection) GetSelected(inputName string) []Profile {
	reader := bufio.NewReader(os.Stdin)
	rSelect := regexp.MustCompile(`(((\d{1,2}\-\d{1,2})|(\d{1,2})),)*(((\d{1,2}\-\d{1,2})|(\d{1,2})),?)`)

	for {
		var name string
		if inputName == "" {
			fmt.Print("Search on Session name: ")
			name, _ = reader.ReadString('\n')
			name = strings.TrimSpace(name)
		} else {
			name = inputName
		}

		query := "SELECT id, name, address, protocol, port, username, password FROM profile WHERE name LIKE ? ORDER BY name"
		rows, err := c.db.Query(query, "%"+name+"%")
		if err != nil {
			fmt.Println("Error querying database:", err)
			return nil
		}

		var profiles []Profile
		for rows.Next() {
			var p Profile
			rows.Scan(&p.ID, &p.Name, &p.Address, &p.Protocol, &p.Port, &p.Username, &p.Password)
			profiles = append(profiles, p)
		}
		rows.Close()

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Name", "Username", "Address", "Protocol", "Port"})

		for i, p := range profiles {
			table.Append([]string{
				strconv.Itoa(i + 1),
				p.Name,
				p.Username,
				p.Address,
				p.Protocol,
				strconv.Itoa(p.Port),
			})
		}
		table.Render()

		if len(profiles) == 1 && profiles[0].Name == name {
			return []Profile{profiles[0]}
		}

		fmt.Print("Select number to connect or r to restart: ")
		selection, _ := reader.ReadString('\n')
		selection = strings.TrimSpace(selection)

		if strings.ToLower(selection) == "r" {
			cmd := exec.Command("reset")
			cmd.Stdout = os.Stdout
			cmd.Run()
			continue
		}

		if selection == "" && len(profiles) > 0 {
			return []Profile{profiles[0]}
		}

		if !rSelect.MatchString(selection) {
			red := color.New(color.FgRed)
			red.Println("selection error, please reselect: ")
			continue
		}

		if selection != "" {
			selections := c.ParseSelection(selection)
			if len(selections) > 0 && selections[len(selections)-1] <= len(profiles) {
				selectedProfiles := []Profile{}
				for _, sel := range selections {
					selectedProfiles = append(selectedProfiles, profiles[sel-1])
				}
				return selectedProfiles
			}
			fmt.Println("wrong index, please reselect: ")
		}
	}
}

func (c *Connection) AddProfile() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("//////////////////////////////////////")
	fmt.Println("//Add connection profile to database: ")
	fmt.Println("//////////////////////////////////////")

	for {
		fmt.Print("Profile Name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)

		fmt.Print("Username (default: admin) : ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		if username == "" {
			username = "admin"
		}

		fmt.Print("Password: ")
		pwdBytes, _ := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		unencPwd := string(pwdBytes)
		var password string
		if unencPwd != "" {
			password, _ = c.enc.Encrypt(unencPwd)
		}

		fmt.Print("connection address: ")
		address, _ := reader.ReadString('\n')
		address = strings.TrimSpace(address)

		var protocol string
		for {
			fmt.Print("Protocol [ssh/ telnet](default: ssh) : ")
			protocol, _ = reader.ReadString('\n')
			protocol = strings.TrimSpace(strings.ToLower(protocol))
			if protocol == "" {
				protocol = "ssh"
			}
			if protocol == "ssh" || protocol == "telnet" {
				break
			}
		}

		defaultPort := 22
		if protocol == "telnet" {
			defaultPort = 23
		}

		fmt.Printf("port(%d): ", defaultPort)
		portStr, _ := reader.ReadString('\n')
		portStr = strings.TrimSpace(portStr)
		port := defaultPort
		if portStr != "" {
			port, _ = strconv.Atoi(portStr)
		}

		_, err := c.db.Exec(`INSERT INTO profile (name, address, protocol, port, username, password) 
			VALUES (?, ?, ?, ?, ?, ?)`, name, address, protocol, port, username, password)
		if err != nil {
			fmt.Println("Error adding profile:", err)
			continue
		}

		fmt.Printf("Session %s added, add more? [y/n]: ", name)
		contAdd, _ := reader.ReadString('\n')
		contAdd = strings.TrimSpace(strings.ToLower(contAdd))
		if contAdd == "n" {
			break
		}
	}
}

func (c *Connection) DeleteProfile() {
	profiles := c.GetSelected("")
	if len(profiles) > 0 {
		for _, p := range profiles {
			_, err := c.db.Exec("DELETE FROM profile WHERE id = ?", p.ID)
			if err != nil {
				fmt.Println("Error deleting profile:", err)
				continue
			}
			fmt.Printf("Session %s is deleted!\n", p.Name)
		}
	} else {
		fmt.Println("No session is selected, exit!")
		os.Exit(1)
	}
}

func (c *Connection) UpdateProfile() {
	profiles := c.GetSelected("")
	if len(profiles) == 0 {
		fmt.Println("No session is selected, exit!")
		os.Exit(1)
	}

	p := profiles[0]
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("//////////////////////////////////////////////////////////")
	fmt.Printf("//Update connection profile %s to database: \n", p.Name)
	fmt.Println("//////////////////////////////////////////////////////////")

	fmt.Printf("Profile Name (%s) [press enter if not change]: ", p.Name)
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name != "" {
		p.Name = name
	}

	fmt.Printf("Username (%s) [press enter if not change]: ", p.Username)
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username != "" {
		p.Username = username
	}

	fmt.Print("Password [press enter if not change]: ")
	pwdBytes, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	unencPwd := string(pwdBytes)
	if unencPwd != "" {
		p.Password, _ = c.enc.Encrypt(unencPwd)
	}

	fmt.Printf("connection address (%s) [press enter if not change]: ", p.Address)
	address, _ := reader.ReadString('\n')
	address = strings.TrimSpace(address)
	if address != "" {
		p.Address = address
	}

	for {
		fmt.Printf("Protocol [%s]: ", p.Protocol)
		protocol, _ := reader.ReadString('\n')
		protocol = strings.TrimSpace(strings.ToLower(protocol))
		if protocol == "" {
			protocol = p.Protocol
		}
		if protocol == "ssh" || protocol == "telnet" {
			p.Protocol = protocol
			break
		}
	}

	defaultPort := 22
	if p.Protocol == "telnet" {
		defaultPort = 23
	}

	fmt.Printf("port(%d): ", defaultPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	if portStr != "" {
		p.Port, _ = strconv.Atoi(portStr)
	} else {
		p.Port = defaultPort
	}

	_, err := c.db.Exec(`UPDATE profile SET name=?, address=?, protocol=?, port=?, username=?, password=? WHERE id=?`,
		p.Name, p.Address, p.Protocol, p.Port, p.Username, p.Password, p.ID)
	if err != nil {
		fmt.Println("Error updating profile:", err)
		os.Exit(1)
	}

	fmt.Printf("Session %s is updated!\n", p.Name)
}

func (c *Connection) EncryptPassword() {
	rows, err := c.db.Query("SELECT id, password FROM profile")
	if err != nil {
		fmt.Println("Error querying profiles:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var password string
		rows.Scan(&id, &password)

		if password == "" {
			continue
		}

		if _, err := base64.StdEncoding.DecodeString(password); err != nil {
			encPwd, _ := c.enc.Encrypt(password)
			c.db.Exec("UPDATE profile SET password=? WHERE id=?", encPwd, id)
		}
	}
}

func (c *Connection) ReleaseToTmux(profile Profile) {
	var cmd string

	if profile.Protocol == "ssh" {
		var decPwd string
		var err error
		if profile.Password != "" {
			decPwd, err = c.enc.Decrypt(profile.Password)
			if err != nil {
				fmt.Printf("Error decrypting password %s for profile %s: %v\n", decPwd, profile.Name, err)
			}
		}

		if decPwd != "" {
			tmpDir := os.Getenv("TMPDIR")
			if tmpDir == "" {
				tmpDir = "/tmp/"
			}
			pwdFile := filepath.Join(tmpDir, "tmux_password")
			os.WriteFile(pwdFile, []byte(decPwd), 0600)
			cmd = fmt.Sprintf("sshpass -f%s ssh -p %d %s@%s", pwdFile, profile.Port, profile.Username, profile.Address)
		} else {
			cmd = fmt.Sprintf("ssh -p %d %s@%s", profile.Port, profile.Username, profile.Address)
		}
	} else if profile.Protocol == "telnet" {
		cmd = fmt.Sprintf("telnet %s %d", profile.Address, profile.Port)
	}

	fmt.Printf("create tmux window %s, send command.\n", profile.Name)

	tmuxCmd := exec.Command("tmux", "new-window", "-t", c.tmuxSession, "-n", profile.Name, "-P", "-F", "#{window_id}")
	output, err := tmuxCmd.Output()
	if err != nil {
		fmt.Println("Error creating tmux window:", err)
		return
	}
	windowID := strings.TrimSpace(string(output))

	sendKeysCmd := exec.Command("tmux", "send-keys", "-t", windowID, cmd, "C-m")
	sendKeysCmd.Run()

	detachCmd := exec.Command("tmux", "detach-client", "-s", tmuxFloaxSession)
	detachCmd.Run()
}

func initDatabase(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

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
	return err
}

func checkTmuxSession(sessionName string) bool {
	cmd := exec.Command("tmux", "has-session", "-t", sessionName)
	err := cmd.Run()
	return err == nil
}

func generateCompletions(conn *Connection, prefix string) {
	actionChoices := []string{"list", "add", "delete", "update", "encrypt", "init"}

	// Get all profile names
	names, err := conn.ListProfileNames()
	if err != nil {
		names = []string{}
	}

	// Combine actions and profile names
	allChoices := append(actionChoices, names...)

	// Filter by prefix
	for _, choice := range allChoices {
		if strings.HasPrefix(choice, prefix) {
			fmt.Println(choice)
		}
	}
}

func printHelp() {
	fmt.Println("Tmux Session Helper - SSH/Telnet Connection Manager")
	fmt.Printf("Author: %s\n\n", author)
	fmt.Println("Usage: connect [OPTION|NAME]")
	fmt.Println("\nOptions:")
	fmt.Println("  -h, --help     Show this help message")
	fmt.Println("  init           Initialize the database")
	fmt.Println("  list           List all connection profiles")
	fmt.Println("  add            Add a new connection profile")
	fmt.Println("  delete         Delete a connection profile")
	fmt.Println("  update         Update an existing connection profile")
	fmt.Println("  encrypt        Encrypt plaintext passwords in database")
	fmt.Println("  NAME           Search and connect to profile(s) by name")
	fmt.Println("\nExamples:")
	fmt.Println("  connect init              # Initialize database")
	fmt.Println("  connect list              # List all profiles")
	fmt.Println("  connect add               # Add new profile")
	fmt.Println("  connect myserver          # Connect to profile matching 'myserver'")
	fmt.Println("\nDatabase: ~/.mess_config/profile.sqlite.db")
	fmt.Println("Password Encryption Key file: ~/.tmux_session_key")
}

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nAlright, Alright!")
		os.Exit(1)
	}()

	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".mess_config", "profile.sqlite.db")
	keyFile := filepath.Join(home, ".tmux_session_key")

	args := os.Args[1:]

	// Handle help option
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		printHelp()
		os.Exit(0)
	}

	// Handle completion mode
	if len(args) >= 2 && args[0] == "--complete" {
		// Skip tmux session check for completions
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			os.Exit(0)
		}

		enc, err := NewEncrypt(keyFile)
		if err != nil {
			os.Exit(0)
		}

		conn, err := NewConnection(enc, dbPath, tmuxSession)
		if err != nil {
			os.Exit(0)
		}
		defer conn.Close()

		prefix := args[1]
		generateCompletions(conn, prefix)
		os.Exit(0)
	}

	if !checkTmuxSession(tmuxSession) {
		fmt.Printf("Tmux session %s not found!\n", tmuxSession)
		os.Exit(-1)
	}

	enc, err := NewEncrypt(keyFile)
	if err != nil {
		fmt.Println("Error initializing encryption:", err)
		os.Exit(1)
	}

	conn, err := NewConnection(enc, dbPath, tmuxSession)
	if err != nil {
		fmt.Println("Error connecting to database:", err)
		os.Exit(1)
	}
	defer conn.Close()

	opt := ""
	if len(args) > 0 {
		opt = args[0]
	}

	switch {
	case opt != "" && strings.HasPrefix("init", opt):
		os.MkdirAll(filepath.Dir(dbPath), 0755)
		if err := initDatabase(dbPath); err != nil {
			fmt.Println("Error initializing database:", err)
			os.Exit(1)
		}
		fmt.Println("Database initialized successfully")
	case opt == "list":
		profiles, err := conn.Profiles()
		if err != nil {
			fmt.Println("Error listing profiles:", err)
			os.Exit(1)
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Name", "Username", "Address", "Protocol", "Port"})

		for i, p := range profiles {
			table.Append([]string{
				strconv.Itoa(i + 1),
				p.Name,
				p.Username,
				p.Address,
				p.Protocol,
				strconv.Itoa(p.Port),
			})
		}
		table.Render()
	case opt == "add":
		conn.AddProfile()
	case opt == "delete":
		conn.DeleteProfile()
	case opt == "update":
		conn.UpdateProfile()
	case opt == "encrypt":
		conn.EncryptPassword()
		fmt.Println("Passwords encrypted successfully")
	default:
		conn.Connect(opt)
	}
}
