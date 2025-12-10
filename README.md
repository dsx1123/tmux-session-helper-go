# TMUX Connection Helper
[![CI](https://github.com/dsx1123/tmux-session-helper-go/actions/workflows/go.yml/badge.svg)](https://github.com/dsx1123/tmux-session-helper-go/actions/workflows/go.yml)

A command-line tool to manage SSH/Telnet connections through tmux windows. This tool helps you organize, search, and quickly connect to remote servers by automatically creating tmux windows with your saved connection profiles.

## Features

- 🔐 **Secure Password Storage**: Encrypts passwords using PBKDF2-derived keys
- 🔍 **Fuzzy Search**: Quickly find and connect to servers by name
- 📦 **Profile Management**: Add, update, delete, and list connection profiles
- 🚀 **Batch Connections**: Connect to multiple servers simultaneously
- 🖥️ **Tmux Integration**: Automatically creates tmux windows for each connection
- ⚡ **Auto-completion**: Built-in shell completion support
- 🔌 **Multi-Protocol**: Supports both SSH and Telnet

## Requirements

- Go 1.16 or higher
- tmux
- sshpass (optional, for SSH password authentication)
- A running tmux session named "default"

## Installation

### From Source

```bash
git clone https://github.com/dsx1123/tmux-session-helper-go.git
cd tmux-session-helper-go
go build -o connect connect.go
sudo mv connect /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/dsx1123/tmux-session-helper-go@latest
```

## Quick Start

1. **Initialize the database**:
   ```bash
   connect init
   ```

2. **Add your first connection profile**:
   ```bash
   connect add
   ```
   Follow the prompts to enter connection details.

3. **Connect to a server**:
   ```bash
   connect myserver
   ```

## Usage

```
connect [OPTION|NAME]

Options:
  -h, --help     Show help message
  init           Initialize the database
  list           List all connection profiles
  add            Add a new connection profile
  delete         Delete a connection profile
  update         Update an existing connection profile
  encrypt        Encrypt plaintext passwords in database
  NAME           Search and connect to profile(s) by name
```

### Examples

**List all profiles**:
```bash
connect list
```

**Add a new server**:
```bash
connect add
# Follow interactive prompts
```

**Connect by name** (fuzzy search):
```bash
connect prod-web
```

**Connect to multiple servers**:
```bash
# After searching, select multiple: 1,3,5 or 1-3
connect database
Select number to connect: 1,3,5
```

**Update a profile**:
```bash
connect update
```

**Delete a profile**:
```bash
connect delete
```

## Configuration

### Database Location
Profiles are stored in: `~/.mess_config/profile.sqlite.db`

### Encryption Key
Master password is stored in: `~/.tmux_session_key`

On first run, you'll be prompted to create this file with your master password.

### Tmux Session
The tool expects a tmux session named "default". Create it with:
```bash
tmux new-session -s default
```

## Shell Auto-completion

### Zsh

1. Copy the completion script to your zsh completions directory:
   ```bash
   sudo cp _connect /usr/local/share/zsh/site-functions/_connect
   ```
   Or for user-level installation:
   ```bash
   mkdir -p ~/.zsh/completion
   cp _connect ~/.zsh/completion/_connect
   # Add to ~/.zshrc:
   fpath=(~/.zsh/completion $fpath)
   ```

2. Reload your shell or run:
   ```bash
   autoload -Uz compinit && compinit
   ```

Auto-completion will suggest both commands (init, list, add, etc.) and profile names.

## How It Works

1. **Profile Storage**: Connection details are stored in a local SQLite database
2. **Encryption**: Passwords are encrypted using XOR cipher with PBKDF2-derived keys (10,000 iterations, SHA-256)
3. **Tmux Integration**: When connecting, the tool creates a new tmux window and sends the connection command
4. **Search**: Type any part of a profile name to filter and select matches

## Security Notes

- Passwords are encrypted at rest using a master password
- The master password is stored in `~/.tmux_session_key` (chmod 600)
- Temporary password files are created in `$TMPDIR` during SSH connection setup
- This tool is designed for convenience in trusted environments

## Profile Schema

Each profile contains:
- **Name**: Identifier for the connection
- **Address**: Hostname or IP address
- **Protocol**: ssh or telnet
- **Port**: Connection port (default: 22 for SSH, 23 for Telnet)
- **Username**: Login username
- **Password**: Encrypted password (optional)

## Troubleshooting

**"Tmux session default not found!"**
- Create a tmux session: `tmux new-session -s default`

**SSH password authentication not working**
- Install sshpass: `sudo apt install sshpass` (Debian/Ubuntu) or `brew install sshpass` (macOS)

**Database errors**
- Reinitialize: `connect init`

**Encryption errors**
- Check `~/.tmux_session_key` exists and is readable
- Try re-encrypting: `connect encrypt`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source. See the repository for license details.

## Author

shangxindu@gmail.com
