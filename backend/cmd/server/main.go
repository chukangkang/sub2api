package main

//go:generate go run github.com/google/wire/cmd/wire

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/setup"
	"github.com/Wei-Shaw/sub2api/internal/web"

	"github.com/gin-gonic/gin"
)

//go:embed VERSION
var embeddedVersion string

// Build-time variables (can be set by ldflags)
var (
	Version          = ""
	Commit           = "unknown"
	Date             = "unknown"
	BuildType        = "source" // "source" for manual builds, "release" for CI builds (set by ldflags)
	LicensePublicKey = "qnmdBw9L6pEU7QLuiHvbDk-va7XOLDdljDjVGUOJr-M"
)

const (
	machineCodePrefix = "mc1."
	licensePrefix     = "lic1."
	machineCodeSalt   = "sub2api-machine-code-salt-v1\n"
	licenseMessage    = "sub2api-license-v1\n"
)

type licenseIdentity struct {
	hostname      string
	machineID     string
	productUUID   string
	productSerial string
	boardSerial   string
	chassisSerial string
}
func init() {
	// 如果 Version 已通过 ldflags 注入（例如 -X main.Version=...），则不要覆盖。
	if strings.TrimSpace(Version) != "" {
		return
	}

	// 默认从 embedded VERSION 文件读取版本号（编译期打包进二进制）。
	Version = strings.TrimSpace(embeddedVersion)
	if Version == "" {
		Version = "0.0.0-dev"
	}
}

// initLogger configures the default slog handler based on gin.Mode().
// In non-release mode, Debug level logs are enabled.
func main() {
	logger.InitBootstrap()
	defer logger.Sync()

	// Parse command line flags
	setupMode := flag.Bool("setup", false, "Run setup wizard in CLI mode")
	showVersion := flag.Bool("version", false, "Show version information")
	showMachineCode := flag.Bool("machine-code", false, "Print this machine's license registration code")
	serialNumber := flag.String("sn", "", "License serial number")
	flag.Parse()

	if *showVersion {
		log.Printf("Sub2API %s (commit: %s, built: %s)\n", Version, Commit, Date)
		return
	}

	if *showMachineCode {
		machineCode, err := registrationMachineCode()
		if err != nil {
			log.Print("Unable to generate machine code")
			return
		}
		fmt.Println(machineCode)
		return
	}

	if strings.TrimSpace(*serialNumber) == "" {
		log.Print("License serial number is required")
		return
	}
	valid, err := verifyLicense(*serialNumber)
	if err != nil {
		log.Printf("License verification failed: %v", err)
		return
	}
	if !valid {
		log.Print("License verification failed")
		return
	}

	// CLI setup mode
	if *setupMode {
		if err := setup.RunCLI(); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		return
	}

	// Check if setup is needed
	if setup.NeedsSetup() {
		// Check if auto-setup is enabled (for Docker deployment)
		if setup.AutoSetupEnabled() {
			log.Println("Auto setup mode enabled...")
			if err := setup.AutoSetupFromEnv(); err != nil {
				log.Fatalf("Auto setup failed: %v", err)
			}
			// Continue to main server after auto-setup
		} else {
			log.Println("First run detected, starting setup wizard...")
			runSetupServer()
			return
		}
	}

	// Normal server mode
	runMainServer()
}

func verifyLicense(serialNumber string) (bool, error) {
	identity, err := collectLicenseIdentity()
	if err != nil {
		return false, err
	}

	encodedPublicKey := strings.TrimSpace(LicensePublicKey)
	if encodedPublicKey == "" {
		return false, errors.New("license public key is not configured")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false, errors.New("license public key is invalid")
	}

	serialNumber = strings.TrimSpace(serialNumber)
	if !strings.HasPrefix(serialNumber, licensePrefix) {
		return false, errors.New("license serial number has an invalid format")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(serialNumber, licensePrefix))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false, errors.New("license serial number has an invalid format")
	}

	machineCode := calculateMachineCode(identity)
	message := []byte(licenseMessage + machineCode)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return false, nil
	}
	return true, nil
}

func registrationMachineCode() (string, error) {
	identity, err := collectLicenseIdentity()
	if err != nil {
		return "", err
	}
	return calculateMachineCode(identity), nil
}

func collectLicenseIdentity() (licenseIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	productUUID, err := readRequiredDMIValue("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return licenseIdentity{}, err
	}
	productSerial, err := readRequiredDMIValue("/sys/class/dmi/id/product_serial")
	if err != nil {
		return licenseIdentity{}, err
	}
	boardSerial, err := readRequiredDMIValue("/sys/class/dmi/id/board_serial")
	if err != nil {
		return licenseIdentity{}, err
	}
	chassisSerial, err := readRequiredDMIValue("/sys/class/dmi/id/chassis_serial")
	if err != nil {
		return licenseIdentity{}, err
	}

	identity := licenseIdentity{
		hostname:      hostname,
		machineID:     readFirstIdentityFile("/etc/machine-id", "/var/lib/dbus/machine-id"),
		productUUID:   productUUID,
		productSerial: productSerial,
		boardSerial:   boardSerial,
		chassisSerial: chassisSerial,
	}
	return identity, nil
}

func readFirstIdentityFile(paths ...string) string {
	for _, path := range paths {
		value := readIdentityFile(path)
		if normalizeLicenseValue(value) != "" {
			return value
		}
	}
	return ""
}

func readIdentityFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readRequiredDMIValue(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil || normalizeLicenseValue(string(data)) == "" {
		return "", errors.New("required machine identity is unavailable")
	}
	return string(data), nil
}

func calculateMachineCode(identity licenseIdentity) string {
	digest := sha256.Sum256([]byte(machineCodeSalt + identity.canonical()))
	return machineCodePrefix + hex.EncodeToString(digest[:])
}

func (identity licenseIdentity) canonical() string {
	return "sub2api-machine-v1\n" +
		"hostname=" + normalizeLicenseValue(identity.hostname) + "\n" +
		"machine-id=" + normalizeLicenseValue(identity.machineID) + "\n" +
		"product-uuid=" + normalizeLicenseValue(identity.productUUID) + "\n" +
		"product-serial=" + normalizeLicenseValue(identity.productSerial) + "\n" +
		"board-serial=" + normalizeLicenseValue(identity.boardSerial) + "\n" +
		"chassis-serial=" + normalizeLicenseValue(identity.chassisSerial) + "\n"
}

func normalizeLicenseValue(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	space := false
	for i := 0; i < len(value); i++ {
		character := value[i]
		if isASCIISpace(character) {
			space = builder.Len() > 0
			continue
		}
		if space {
			builder.WriteByte(' ')
			space = false
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		builder.WriteByte(character)
	}
	return builder.String()
}

func isASCIISpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

func runSetupServer() {
	r := gin.New()
	r.Use(middleware.Recovery())
	r.Use(middleware.CORS(config.CORSConfig{}))
	r.Use(middleware.SecurityHeaders(config.CSPConfig{Enabled: true, Policy: config.DefaultCSPPolicy}, nil))

	// Register setup routes
	setup.RegisterRoutes(r)

	// Serve embedded frontend if available
	if web.HasEmbeddedFrontend() {
		r.Use(web.ServeEmbeddedFrontend())
	}

	// Get server address from config.yaml or environment variables (SERVER_HOST, SERVER_PORT)
	// This allows users to run setup on a different address if needed
	addr := config.GetServerAddress()
	log.Printf("Setup wizard available at http://%s", addr)
	log.Println("Complete the setup wizard to configure Sub2API")

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	server := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		Protocols:         protocols,
	}

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start setup server: %v", err)
	}
}

func runMainServer() {
	cfg, err := config.LoadForBootstrap()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := logger.Init(logger.OptionsFromConfig(cfg.Log)); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	if cfg.RunMode == config.RunModeSimple {
		log.Println("⚠️  WARNING: Running in SIMPLE mode - billing and quota checks are DISABLED")
	}

	buildInfo := handler.BuildInfo{
		Version:   Version,
		BuildType: BuildType,
	}

	app, err := initializeApplication(buildInfo)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.Cleanup()
	if app.PluginManager != nil {
		if err := app.PluginManager.Start(context.Background()); err != nil {
			log.Printf("Plugin manager started in degraded state: %v", err)
		}
	}
	if app.PromptAudit != nil {
		if err := app.PromptAudit.Start(context.Background()); err != nil {
			// Startup continues so unrelated APIs stay up. Fail-closed (unavailable)
			// applies only when a persisted blocking policy was observed; without
			// blocking intent, Prompt Audit stays ModeOff so the gateway remains
			// usable and administrators can still disable the feature (#4560).
			log.Printf("Prompt Audit started in degraded state: %v", err)
		}
	}

	// 启动服务器
	go func() {
		if err := app.Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("Server started on %s", app.Server.Addr)

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.Server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
