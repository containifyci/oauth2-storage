package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/containifyci/go-self-update/pkg/updater"

	"github.com/containifyci/oauth2-storage/pkg/service"
)

var (
	version          = "dev"
	commit           = "none"
	date             = "unknown"
)

func main() {
	fmt.Printf("github-oauth2-service %s, commit %s, built at %s\n", version, commit, date)

	command := "start"
	if len(os.Args) >= 2 {
		command = os.Args[1]
	}

	fmt.Printf("Command: %s\n", command)

	// Get the command
	switch command {
	case "update":
		u := updater.NewUpdater(
			"oauth2-storage", "containifyci", "oauth2-storage", version,
		)
		updated, err := u.SelfUpdate()
		if err != nil {
			fmt.Printf("Update failed %+v\n", err)
		}
		if updated {
			fmt.Println("Update completed successfully!")
			return
		}
		fmt.Println("Already up-to-date")
	case "start":
		fallthrough
	default:
		fmt.Printf("start command: %s\n", command)
		start()
	}
}

func start() {

	storageFile := flag.String("storage", "data.json", "The file to persist the tokens between restarts.")
	publicKey := flag.String("publicKey", "", "The publuc key base64 encode to verify the JWT tokens with.")
	grpcPort := flag.Int("grpcport", 50051, "The port to start the grpc server.")
	httpPort := flag.Int("httpport", 8081, "The port to start the http server.")
	debug := flag.Bool("debug", false, "Enable debug logging.")

	initLogger(*debug)

	err := service.StartServers(service.Config{
		StorageFile:     *storageFile,
		PublicKey:       *publicKey,
		GRPCPort:        *grpcPort,
		HTTPPort:        *httpPort,
		PodNamespace:    getenv("POD_NAMESPACE", ""),
		TokenSyncPeriod: getenv("TOKEN_SYNC_PERIOD", "0m"),
	})
	if err != nil {
		panic(err)
	}
}

func initLogger(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}
