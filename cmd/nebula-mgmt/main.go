package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/juev/nebula-mgmt/internal/cli"
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
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: nebula-mgmt <command> [flags]")
	fmt.Fprintln(os.Stderr, "commands: init, serve, host, network")
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}
	return cli.Serve(*configPath)
}

func runHost(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: nebula-mgmt host <create|list>")
	}

	switch args[0] {
	case "create":
		return runHostCreate(args[1:])
	case "list":
		return runHostList(args[1:])
	default:
		return fmt.Errorf("unknown host subcommand: %s", args[0])
	}
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
