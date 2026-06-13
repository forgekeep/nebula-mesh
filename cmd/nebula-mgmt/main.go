package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/cli"
	"github.com/forgekeep/nebula-mesh/internal/version"
)

// Populated at build time via -ldflags (see .goreleaser.yml).
var (
	versionStr = "dev"
	commit     = "none"
	date       = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return fmt.Errorf("no command specified")
	}

	switch os.Args[1] {
	case "init":
		return runInit(os.Args[2:])
	case "serve":
		return runServe(os.Args[2:])
	case "host":
		return runHost(os.Args[2:])
	case "network":
		return runNetwork(os.Args[2:])
	case "user":
		return runUser(os.Args[2:])
	case "apikey":
		return runAPIKey(os.Args[2:])
	case "ca":
		return runCA(os.Args[2:])
	case "ops":
		return runOps(os.Args[2:])
	case "version", "--version", "-v":
		version.Print(os.Stdout, "nebula-mgmt", versionStr, commit, date)
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: nebula-mgmt <command> [flags]")
	fmt.Fprintln(os.Stderr, "commands: init, serve, host, network, user, apikey, ca, ops, version")
	fmt.Fprintln(os.Stderr, "  host <create|list|delete|block|unblock>")
	fmt.Fprintln(os.Stderr, "  network <create|list>")
	fmt.Fprintln(os.Stderr, "  user <create|list|disable|enable>")
	fmt.Fprintln(os.Stderr, "  apikey <create|revoke>")
	fmt.Fprintln(os.Stderr, "  ca <create|list|delete|rotate>")
	fmt.Fprintln(os.Stderr, "  ops <mint-admin-key>")
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return cli.Init(*configPath)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path (required)")
	insecureHTTP := fs.Bool("insecure-http", false, "allow serving plaintext HTTP on a non-loopback address (overrides allow_insecure_http; credentials transit in cleartext)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}
	return cli.Serve(*configPath, *insecureHTTP)
}

func runHost(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt host <create|list|delete|block|unblock>")
	}

	switch args[0] {
	case "create":
		return runHostCreate(args[1:])
	case "list":
		return runHostList(args[1:])
	case "delete":
		return runHostAction(args[1:], "host delete", cli.HostDelete)
	case "block":
		return runHostAction(args[1:], "host block", cli.HostBlock)
	case "unblock":
		return runHostAction(args[1:], "host unblock", cli.HostUnblock)
	default:
		return fmt.Errorf("unknown host subcommand: %s", args[0])
	}
}

func runHostAction(args []string, name string, action func(serverURL, apiKey, hostID string) error) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	id := fs.String("id", "", "host ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *apiKey == "" {
		return fmt.Errorf("--id and --api-key are required")
	}
	return action(*server, *apiKey, *id)
}

func runHostCreate(args []string) error {
	fs := flag.NewFlagSet("host create", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	networkID := fs.String("network", "", "network ID")
	name := fs.String("name", "", "host name")
	nebulaIP := fs.String("ip", "", "nebula IP")
	role := fs.String("role", "host", "host role (host, lighthouse, relay)")
	groups := fs.String("groups", "", "comma-separated groups")
	publicIP := fs.String("public-ip", "", "public IP (for lighthouse/relay)")
	listenPort := fs.Int("listen-port", 0, "listen port (for lighthouse/relay)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" || *nebulaIP == "" || *networkID == "" || *apiKey == "" {
		return fmt.Errorf("--name, --ip, --network, and --api-key are required")
	}

	var groupList []string
	if *groups != "" {
		groupList = strings.Split(*groups, ",")
	}

	return cli.HostCreate(*server, *apiKey, *networkID, *name, *nebulaIP, *role, groupList, *publicIP, *listenPort)
}

func runHostList(args []string) error {
	fs := flag.NewFlagSet("host list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	networkID := fs.String("network", "", "filter by network ID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}

	return cli.HostList(*server, *apiKey, *networkID)
}

func runNetwork(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt network <create|list>")
	}

	switch args[0] {
	case "create":
		return runNetworkCreate(args[1:])
	case "list":
		return runNetworkList(args[1:])
	default:
		return fmt.Errorf("unknown network subcommand: %s", args[0])
	}
}

func runNetworkCreate(args []string) error {
	fs := flag.NewFlagSet("network create", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	name := fs.String("name", "", "network name")
	cidr := fs.String("cidr", "", "network CIDR")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" || *cidr == "" || *apiKey == "" {
		return fmt.Errorf("--name, --cidr, and --api-key are required")
	}

	return cli.NetworkCreate(*server, *apiKey, *name, *cidr)
}

func runUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt user <create|list|disable|enable>")
	}
	switch args[0] {
	case "create":
		return runUserCreate(args[1:])
	case "list":
		return runUserList(args[1:])
	case "disable":
		return runHostAction(args[1:], "user disable", cli.UserDisable)
	case "enable":
		return runHostAction(args[1:], "user enable", cli.UserEnable)
	default:
		return fmt.Errorf("unknown user subcommand: %s", args[0])
	}
}

func runUserCreate(args []string) error {
	fs := flag.NewFlagSet("user create", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	username := fs.String("username", "", "operator username")
	password := fs.String("password", "", "operator password")
	displayName := fs.String("display-name", "", "operator display name")
	role := fs.String("role", "admin", "operator role")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	return cli.UserCreate(*server, *apiKey, *username, *password, *displayName, *role)
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	return cli.UserList(*server, *apiKey)
}

func runCA(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt ca <create|list|delete|rotate>")
	}
	switch args[0] {
	case "create":
		return runCACreate(args[1:])
	case "list":
		return runCAList(args[1:])
	case "delete":
		return runHostAction(args[1:], "ca delete", cli.CADelete)
	case "rotate":
		return runCARotate(args[1:])
	default:
		return fmt.Errorf("unknown ca subcommand: %s", args[0])
	}
}

func runCACreate(args []string) error {
	fs := flag.NewFlagSet("ca create", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key (must belong to a real operator, not the legacy config key)")
	name := fs.String("name", "", "CA name")
	duration := fs.String("duration", "8760h", "CA lifetime, Go duration string (default 1 year)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" || *name == "" {
		return fmt.Errorf("--api-key and --name are required")
	}
	return cli.CACreate(*server, *apiKey, *name, *duration)
}

func runCAList(args []string) error {
	fs := flag.NewFlagSet("ca list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	return cli.CAList(*server, *apiKey)
}

func runCARotate(args []string) error {
	fs := flag.NewFlagSet("ca rotate", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: nebula-mgmt ca rotate [flags] <id>")
	}
	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	id := fs.Arg(0)
	return cli.CARotate(*server, *apiKey, id)
}

func runAPIKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt apikey <create|revoke>")
	}
	switch args[0] {
	case "create":
		return runAPIKeyCreate(args[1:])
	case "revoke":
		return runAPIKeyRevoke(args[1:])
	default:
		return fmt.Errorf("unknown apikey subcommand: %s", args[0])
	}
}

func runAPIKeyCreate(args []string) error {
	fs := flag.NewFlagSet("apikey create", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	operator := fs.String("operator", "", "operator ID")
	name := fs.String("name", "", "key name (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" || *operator == "" {
		return fmt.Errorf("--api-key and --operator are required")
	}
	return cli.APIKeyCreate(*server, *apiKey, *operator, *name)
}

func runAPIKeyRevoke(args []string) error {
	fs := flag.NewFlagSet("apikey revoke", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	operator := fs.String("operator", "", "operator ID")
	id := fs.String("id", "", "API key ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apiKey == "" || *operator == "" || *id == "" {
		return fmt.Errorf("--api-key, --operator, --id are required")
	}
	return cli.APIKeyRevoke(*server, *apiKey, *operator, *id)
}

func runNetworkList(args []string) error {
	fs := flag.NewFlagSet("network list", flag.ExitOnError)
	server := fs.String("server", "http://localhost:8080", "management server URL")
	apiKey := fs.String("api-key", "", "API key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}

	return cli.NetworkList(*server, *apiKey)
}

func runOps(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt ops <mint-admin-key|backup|restore>")
	}
	switch args[0] {
	case "mint-admin-key":
		return runOpsMintAdminKey(args[1:])
	case "backup":
		return runOpsBackup(args[1:])
	case "restore":
		return runOpsRestore(args[1:])
	default:
		return fmt.Errorf("unknown ops subcommand: %s", args[0])
	}
}

func runOpsBackup(args []string) error {
	fs := flag.NewFlagSet("ops backup", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path (required)")
	output := fs.String("output", "", "backup archive path (required)")
	passphrase := fs.String("passphrase", "", "encrypt the archive with this passphrase (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *output == "" {
		return fmt.Errorf("--config and --output are required")
	}
	return cli.OpsBackup(*configPath, *output, *passphrase, versionStr)
}

func runOpsRestore(args []string) error {
	fs := flag.NewFlagSet("ops restore", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path (required)")
	input := fs.String("input", "", "backup archive path (required)")
	passphrase := fs.String("passphrase", "", "passphrase for an encrypted archive")
	force := fs.Bool("force", false, "replace an existing database (moved aside to <db>.pre-restore)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *input == "" {
		return fmt.Errorf("--config and --input are required")
	}
	return cli.OpsRestore(*configPath, *input, *passphrase, *force)
}

func runOpsMintAdminKey(args []string) error {
	fs := flag.NewFlagSet("ops mint-admin-key", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}
	return cli.OpsMintAdminKey(*configPath)
}
