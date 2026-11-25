// Package config loads process configuration from the environment and
// validates it up front.
//
// Validation is aggregated and fail-fast: a process reports every missing
// variable at startup rather than discovering them one at a time, several
// minutes in, on the first request that happens to need one. The inherited
// evaluator had the opposite behaviour — a missing OPENAI_API_KEY surfaced as a
// per-action runtime failure rather than a boot failure.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Environment variable names. These are the strings reported back to the
// operator when something is missing, so they are the single source of truth.
const (
	EnvPostgresDSN      = "POSTGRES_DSN"
	EnvListenAddr       = "LISTEN_ADDR"
	EnvUpstreamBaseURL  = "UPSTREAM_BASE_URL"
	EnvUpstreamAPIKey   = "UPSTREAM_API_KEY"
	EnvToolRegistryPath = "TOOL_REGISTRY_PATH"
	EnvJWTIssuer        = "JWT_ISSUER"
	EnvJWTAudience      = "JWT_AUDIENCE"
	EnvJWTPublicKeyPath = "JWT_PUBLIC_KEY_PATH"
	EnvLlamaGuardURL    = "LLAMA_GUARD_URL"
	EnvLlamaGuardModel  = "LLAMA_GUARD_MODEL"

	// Durations are parsed rather than stored as strings, so they are absent
	// from fields() and from the requirement sets: both have defaults.
	EnvInspectTimeout  = "INSPECT_TIMEOUT"
	EnvUpstreamTimeout = "UPSTREAM_TIMEOUT"

	// Corpus capture. Off by default: storing prompts verbatim is a liability
	// the rest of the schema is designed to avoid, and is only worth it while
	// there is a corpus to label.
	EnvCaptureRawContent   = "CAPTURE_RAW_CONTENT"
	EnvRawContentRetention = "RAW_CONTENT_RETENTION"
)

// Defaults.
//
// InspectTimeout is the budget for the whole inbound inspection phase, not per
// inspector: every leg runs concurrently under one deadline. UpstreamTimeout is
// far larger because a model writing a long answer is not a fault.
const (
	defaultListenAddr      = ":8080"
	defaultLlamaGuardModel = "llama-guard3:8b"
	defaultInspectTimeout  = 2 * time.Second
	defaultUpstreamTimeout = 5 * time.Minute

	// Short on purpose. Capture is a bounded exercise, and a retention window
	// that outlives the labelling run quietly becomes permanent storage.
	defaultRawContentRetention = 7 * 24 * time.Hour
)

// Requirement sets per component. A process requires only what it actually
// uses, so the gateway does not demand chain credentials it never touches.
// RequiredForGateway is what the proxy needs to start.
//
// LLAMA_GUARD_URL is deliberately absent: phase 3 does not call the semantic
// gate, and demanding a URL the process never uses means a pass-through proxy
// refuses to boot for no reason. Phase 4 adds it to RequiredForInspection.
var (
	RequiredForGateway = []string{
		EnvPostgresDSN,
		EnvUpstreamBaseURL,
		EnvToolRegistryPath,
		EnvJWTIssuer,
		EnvJWTAudience,
		EnvJWTPublicKeyPath,
	}

	// RequiredForInspection is additionally required once the semantic gate is
	// wired (phase 4).
	RequiredForInspection = []string{EnvLlamaGuardURL}

	RequiredForMigrate = []string{EnvPostgresDSN}
)

// Config holds every value this project reads from the environment.
type Config struct {
	PostgresDSN string

	// Gateway.
	ListenAddr       string
	UpstreamBaseURL  string
	UpstreamAPIKey   string
	ToolRegistryPath string

	// Identity. The gateway verifies tokens with a public key, so it never
	// holds the key that mints them.
	JWTIssuer        string
	JWTAudience      string
	JWTPublicKeyPath string

	// Inspection (phase 4).
	LlamaGuardURL string

	// LlamaGuardModel is a config value rather than a constant so 8B and 1B can
	// be compared on the same traffic once there is a corpus to compare them
	// with.
	LlamaGuardModel string

	// Budgets. Separate on purpose: inspection must finish inside a tight
	// deadline, while a model generating a long answer legitimately takes much
	// longer. One shared timeout would either cut off generation or let a hung
	// inspector hold the request open.
	InspectTimeout  time.Duration
	UpstreamTimeout time.Duration

	// CaptureRawContent stores the inspected text verbatim alongside its hash
	// and preview, and records clean verdicts as well as findings.
	//
	// Both are needed to build an evaluation corpus and neither is wanted
	// permanently: a false-positive rate cannot be computed from positives
	// alone, and prompts kept forever make the audit log the system of record
	// for the material it exists to catch. Turn it on for a labelling run,
	// then off.
	CaptureRawContent bool

	// RawContentRetention is how long captured text survives. Nothing writes
	// raw content without stamping an expiry from this.
	RawContentRetention time.Duration
}

// getenv is swappable so tests can supply an environment without mutating the
// real one, which keeps them safe to run in parallel.
type getenv func(string) string

// Load reads configuration, first loading a .env file if one is present. A
// missing .env is not an error; a missing variable is only an error once
// Require says it is.
func Load() Config {
	loadDotEnv()
	return loadFrom(osGetenv)
}

// loadDotEnv finds a .env by walking up from the working directory.
//
// godotenv.Load() with no argument only looks in the process's working
// directory. A binary started from overseer/cmd/gateway would therefore find
// nothing and then fail Require with a list of "missing" variables that are
// sitting in the repo root — an error message that sends you looking in exactly
// the wrong place.
//
// Variables already present in the environment win, so this never overrides a
// deliberate setting.
func loadDotEnv() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for {
		candidate := filepath.Join(dir, ".env")
		if _, err := os.Stat(candidate); err == nil {
			_ = godotenv.Load(candidate)
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return // reached the filesystem root; no .env anywhere above us
		}
		dir = parent
	}
}

// fields maps every environment variable name onto the Config field it fills.
//
// Loading and lookup both go through this one table, because the alternative is
// writing the variable list out three times — the constants, the assignments
// that read the environment, and a switch that resolves a name back to a value
// — and the failure mode of a missed third copy is quiet and confusing: the
// variable loads fine, and Require insists it is missing however carefully the
// operator sets it. Adding a variable here is one edit, and an entry that is
// absent is absent from both halves at once.
func (c *Config) fields() map[string]*string {
	return map[string]*string{
		EnvPostgresDSN:      &c.PostgresDSN,
		EnvListenAddr:       &c.ListenAddr,
		EnvUpstreamBaseURL:  &c.UpstreamBaseURL,
		EnvUpstreamAPIKey:   &c.UpstreamAPIKey,
		EnvToolRegistryPath: &c.ToolRegistryPath,
		EnvJWTIssuer:        &c.JWTIssuer,
		EnvJWTAudience:      &c.JWTAudience,
		EnvJWTPublicKeyPath: &c.JWTPublicKeyPath,
		EnvLlamaGuardURL:    &c.LlamaGuardURL,
		EnvLlamaGuardModel:  &c.LlamaGuardModel,
	}
}

func loadFrom(get getenv) Config {
	c := Config{
		InspectTimeout:      defaultInspectTimeout,
		UpstreamTimeout:     defaultUpstreamTimeout,
		RawContentRetention: defaultRawContentRetention,
	}
	for key, field := range c.fields() {
		*field = strings.TrimSpace(get(key))
	}
	if d, err := time.ParseDuration(strings.TrimSpace(get(EnvInspectTimeout))); err == nil && d > 0 {
		c.InspectTimeout = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(get(EnvUpstreamTimeout))); err == nil && d > 0 {
		c.UpstreamTimeout = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(get(EnvRawContentRetention))); err == nil && d > 0 {
		c.RawContentRetention = d
	}
	// Anything other than an explicit truthy value leaves capture off. A
	// mistyped variable must not silently start storing prompts.
	switch strings.ToLower(strings.TrimSpace(get(EnvCaptureRawContent))) {
	case "1", "true", "yes", "on":
		c.CaptureRawContent = true
	}
	if c.ListenAddr == "" {
		c.ListenAddr = defaultListenAddr
	}
	if c.LlamaGuardModel == "" {
		c.LlamaGuardModel = defaultLlamaGuardModel
	}
	return c
}

// Require reports every requested variable that is empty, naming each one. A
// name this package does not know is reported as missing rather than passed
// over, so a typo in a requirement set fails the process instead of quietly
// checking nothing.
func (c Config) Require(keys ...string) error {
	fields := c.fields()

	var missing []string
	for _, k := range keys {
		field, known := fields[k]
		if !known || *field == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("missing required environment %s: %s",
		pluralise(len(missing), "variable", "variables"), strings.Join(missing, ", "))
}

func pluralise(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
