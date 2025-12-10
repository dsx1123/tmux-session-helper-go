# TMUX Connection Helper
[![CI](https://github.com/dsx1123/tmux-session-helper-go/actions/workflows/go.yml/badge.svg)](https://github.com/dsx1123/tmux-session-helper-go/actions/workflows/go.yml)

This is a tool I used daily to  start a new tmux window and open an connection ssh/telnet to a remote server.
It requires sshpass if you want to use password authentication. The password is stored in the sqlite database encrypted with a master password you provided.

## Zsh Autocompletion

To enable zsh autocompletion:

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
