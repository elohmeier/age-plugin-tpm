package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/foxboron/age-plugin-tpm/plugin"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type PluginOptions struct {
	AgePlugin         string
	Convert           bool
	Generate          bool
	Decrypt           bool
	Encrypt           bool
	OutputFile        string
	LogFile           string
	OldStyleRecipient bool
	PIN               bool
	Agent             bool
	AgentSocket       string
	AgentTimeout      time.Duration
	Unlock            string
	Lock              bool
	AgentStatus       bool
}

var example = `
  $ age-plugin-tpm --generate -o age-identity.txt
  # Created: 2023-07-10 22:13:57.864450969 +0200 CEST m=+0.475252114
  # Recipient: age1tpm1qt92lcdxj75rjz9e4t9nud7fv6t2cfn8rhzdfnc0z2rnfgv3cqwrqgme4dq

  AGE-PLUGIN-TPM-1QYQQQKQQYVQQKQQZQPEQQQQQZQQPJQQTQQPSQYQQYR92LCDXJ75RJZ9E4T9NUD7[...]

  $ echo "Hello World" | age -r "age1tpm1syqqqpqrtxsnkkqlmu505zzrq439hetls4qwwmyhsv8dgjhksvtewvx29lxs7s68qy" > secret.age

  $ age --decrypt -i age-identity.txt -o - secret.age
  Hello World`

var (
	version       = "dev"
	pluginOptions = PluginOptions{}
	rootCmd       = &cobra.Command{
		Use:     "age-plugin-tpm",
		Long:    "age-plugin-tpm is a tool to generate age compatible identities backed by a TPM.",
		Example: example,
		Version: version,
		RunE:    RunPlugin,
	}
)

func SetLogger() {
	var w io.Writer
	if pluginOptions.LogFile != "" {
		w, _ = os.Open(pluginOptions.LogFile)
	} else if os.Getenv("AGEDEBUG") != "" {
		w = os.Stderr
	} else {
		w = io.Discard
	}
	plugin.SetLogger(w)
}

func GetPin(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s ", prompt)
	defer fmt.Fprintln(os.Stderr)
	return term.ReadPassword(int(os.Stdin.Fd()))
}

// createOutputFile creates a new private output file, and its directory if
// needed, so that a generated key is never lost to a missing directory.
func createOutputFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("output file %s already exists", path)
	}
	return f, err
}

func RunCli(cmd *cobra.Command, tpm transport.TPMCloser, in io.Reader, out io.Writer) error {
	var pin []byte
	var err error
	switch {
	case pluginOptions.Generate:
		// Create the output file before asking for a PIN, so that problems
		// with it are reported first.
		var outputFile *os.File
		if pluginOptions.OutputFile != "" && pluginOptions.OutputFile != "-" {
			outputFile, err = createOutputFile(pluginOptions.OutputFile)
			if err != nil {
				return err
			}
			defer func() {
				outputFile.Close()
				if err != nil {
					os.Remove(outputFile.Name())
				}
			}()
			out = outputFile
		}

		if pluginOptions.PIN {
			if s := os.Getenv("AGE_TPM_PIN"); s != "" {
				pin = []byte(s)
			} else {
				pin, err = GetPin("Enter pin for key:")
				if err != nil {
					return err
				}
				var confirm []byte
				confirm, err = GetPin("Confirm pin:")
				if err != nil {
					return err
				}
				if !bytes.Equal(pin, confirm) {
					err = fmt.Errorf("pins didn't match")
					return err
				}
			}
		}

		var rcp fmt.Stringer
		var identity *plugin.Identity
		var recipient fmt.Stringer
		identity, recipient, err = plugin.CreateIdentity(tpm, pin)
		if err != nil {
			return err
		}
		rcp = recipient
		if pluginOptions.OldStyleRecipient {
			rcp = identity.TPMRecipient()
		}
		if err = plugin.MarshalIdentity(identity, rcp, out); err != nil {
			return err
		}
		if outputFile != nil {
			fmt.Fprintf(os.Stderr, "Public key: %s\n", rcp)
		}
	case pluginOptions.Convert:
		if pluginOptions.OutputFile != "" && pluginOptions.OutputFile != "-" {
			f, err := os.OpenFile(pluginOptions.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			out = f
		}
		identity, err := plugin.ParseIdentity(in)
		if err != nil {
			return err
		}
		var recipient fmt.Stringer
		if pluginOptions.OldStyleRecipient {
			recipient = identity.TPMRecipient()
		} else {
			recipient, err = identity.Recipient()
			if err != nil {
				return err
			}
		}
		return plugin.MarshalRecipient(recipient, out)
	default:
		return cmd.Help()
	}
	return nil
}

func agentSocket() string {
	if pluginOptions.AgentSocket != "" {
		return pluginOptions.AgentSocket
	}
	return plugin.DefaultAgentSocket()
}

// RunAgent serves the unlock agent until SIGINT or SIGTERM.
func RunAgent() error {
	if err := plugin.HardenProcess(); err != nil {
		return fmt.Errorf("failed hardening process: %v", err)
	}
	tpm, err := plugin.NewTPM("")
	if err != nil {
		return err
	}
	defer tpm.Close()

	l, cleanup, err := plugin.AgentListener(agentSocket())
	if err != nil {
		return err
	}
	defer cleanup()

	agent := plugin.NewAgent(tpm, pluginOptions.AgentTimeout)
	defer agent.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		l.Close()
	}()
	return agent.Serve(l)
}

// RunUnlock reads the PIN for the identity file and hands it to the agent.
func RunUnlock(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	identity, err := plugin.ParseIdentity(f)
	if err != nil {
		return err
	}
	if !identity.HasPIN() {
		return nil
	}
	agent := plugin.NewAgentClient(agentSocket())
	for attempt := 1; ; attempt++ {
		var pin []byte
		envPIN := os.Getenv("AGE_TPM_PIN")
		switch {
		case envPIN != "":
			pin = []byte(envPIN)
		case term.IsTerminal(int(os.Stdin.Fd())):
			pin, err = GetPin("Enter pin for key:")
			fmt.Fprintln(os.Stderr)
		default:
			pin, err = GetPinPinentry("Unlock the age TPM identity "+file, "PIN:")
		}
		if err != nil {
			return err
		}
		err = agent.Unlock(identity, pin)
		clear(pin)
		if errors.Is(err, plugin.ErrAgentBadPassword) && attempt < 2 && envPIN == "" {
			fmt.Fprintln(os.Stderr, "Incorrect PIN, try again.")
			continue
		}
		return err
	}
}

func RunPlugin(cmd *cobra.Command, args []string) error {
	switch {
	case pluginOptions.Agent:
		return RunAgent()
	case pluginOptions.Unlock != "":
		return RunUnlock(pluginOptions.Unlock)
	case pluginOptions.Lock:
		return plugin.NewAgentClient(agentSocket()).Lock()
	case pluginOptions.AgentStatus:
		n, err := plugin.NewAgentClient(agentSocket()).Status()
		if err != nil {
			return err
		}
		fmt.Printf("%d identities unlocked\n", n)
		return nil
	}

	switch pluginOptions.AgePlugin {
	case "recipient-v1":
		plugin.Log.Println("Got recipient-v1")
		p, err := page.New("tpm")
		if err != nil {
			return err
		}
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			if p != nil {
				if err := p.DisplayMessage("The recipient was created with a previous version of age-plugin-tpm, please convert or create a new recipient."); err != nil {
					return nil, fmt.Errorf("failed displaying message: %v", err)
				}
			}
			return tag.NewClassicRecipient(data)
		})
		if exitCode := p.RecipientV1(); exitCode != 0 {
			return fmt.Errorf("age-plugin exited with code %d", exitCode)
		}
	case "identity-v1":
		var agent *plugin.AgentClient
		if os.Getenv("AGE_PLUGIN_NO_AGENT") == "" {
			if c := plugin.NewAgentClient(plugin.DefaultAgentSocket()); c.Available() {
				agent = c
			}
		}
		// With an agent the plugin doesn't need TPM access itself.
		var tpm transport.TPMCloser
		if agent == nil {
			var err error
			tpm, err = plugin.NewTPM("")
			if err != nil {
				return err
			}
			defer tpm.Close()
		}
		plugin.Log.Println("Got identity-v1")
		p, err := page.New("tpm")
		if err != nil {
			return err
		}
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			i, err := plugin.DecodeIdentity(page.EncodeIdentity("tpm", data))
			if err != nil {
				return nil, err
			}
			// Set callbacks for TPM and PIN access
			i.Callbacks(p, tpm,
				func() ([]byte, error) {
					var pin []byte
					if s := os.Getenv("AGE_TPM_PIN"); s != "" {
						pin = []byte(s)
					} else {
						ps, err := p.RequestValue("Please enter the PIN for the key:", true)
						if err != nil {
							return nil, err
						}
						pin = []byte(ps)
					}
					return pin, nil
				},
			)
			if agent != nil {
				i.UseAgent(agent)
			}
			return i, nil
		})
		os.Exit(p.Main())
	default:
		tpm, err := plugin.NewTPM("")
		if err != nil {
			return err
		}
		defer tpm.Close()
		in := os.Stdin
		if inFile := cmd.Flags().Arg(0); inFile != "" && inFile != "-" {
			f, err := os.Open(inFile)
			if err != nil {
				return fmt.Errorf("failed to open input file %q: %v", inFile, err)
			}
			defer f.Close()
			in = f
		}
		return RunCli(cmd, tpm, in, os.Stdout)
	}
	return nil
}

func pluginFlags(cmd *cobra.Command, opts *PluginOptions) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.BoolVarP(&pluginOptions.Convert, "convert", "y", false, "Convert identities to recipients.")
	flags.StringVarP(&pluginOptions.OutputFile, "output", "o", "", "Write the result to the file.")

	flags.BoolVarP(&pluginOptions.Generate, "generate", "g", false, "Generate a identity.")
	flags.BoolVarP(&pluginOptions.PIN, "pin", "p", false, "Include a pin with the key. Alternatively export AGE_TPM_PIN.")

	// Debug or logging stuff
	flags.StringVar(&pluginOptions.LogFile, "log-file", "", "Logging file for debug output")

	// Unlock agent
	flags.BoolVar(&pluginOptions.Agent, "agent", false, "Run the unlock agent, which caches PINs until it stops or --lock.")
	flags.StringVar(&pluginOptions.AgentSocket, "socket", "", "Agent socket path (default $AGE_PLUGIN_TPM_AGENT_SOCK or $XDG_RUNTIME_DIR/age-plugin-tpm/agent.sock).")
	flags.DurationVar(&pluginOptions.AgentTimeout, "timeout", 0, "Forget cached PINs this long after unlocking (default: never).")
	flags.StringVar(&pluginOptions.Unlock, "unlock", "", "Unlock the identity file in the agent.")
	flags.BoolVar(&pluginOptions.Lock, "lock", false, "Make the agent forget all cached PINs.")
	flags.BoolVar(&pluginOptions.AgentStatus, "agent-status", false, "Show how many identities the agent has unlocked.")

	// Old style recipient
	flags.BoolVar(&pluginOptions.OldStyleRecipient, "tpm-recipient", false, "Use the old-style tpm recipient instead of the new p256tag recipient.")

	// Hidden commands
	flags.BoolVar(&pluginOptions.Decrypt, "decrypt", false, "wip")
	flags.BoolVar(&pluginOptions.Encrypt, "encrypt", false, "wip")
	flags.StringVar(&pluginOptions.AgePlugin, "age-plugin", "", "internal use")
	flags.MarkHidden("decrypt")
	flags.MarkHidden("encrypt")
	flags.MarkHidden("age-plugin")
}

func main() {
	SetLogger()
	pluginFlags(rootCmd, &pluginOptions)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "age-plugin-tpm: error: %v\n", err)
		os.Exit(1)
	}
}
