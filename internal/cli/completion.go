package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewCompletionCmd creates the completion command
func NewCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for vault.

To load completions:

Bash:
  $ source <(vault completion bash)

  To load completions for each session, execute once:
  Linux:
    $ vault completion bash > /etc/bash_completion.d/vault
  macOS:
    $ vault completion bash > $(brew --prefix)/etc/bash_completion.d/vault

Zsh:
  If shell completion is not already enabled, enable it by adding to ~/.zshrc:
    autoload -Uz compinit
    compinit

  Then:
    $ vault completion zsh > "${fpath[1]}/_vault"

  Start a new shell for the setup to take effect.

Fish:
  $ vault completion fish > ~/.config/fish/completions/vault.fish

PowerShell:
  PS> vault completion powershell | Out-String | Invoke-Expression

  To load completions for each session, add to your PowerShell profile:
  PS> vault completion powershell > vault.ps1
  Add the following line to your $PROFILE:
    & path\to\vault.ps1
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}

	return cmd
}
