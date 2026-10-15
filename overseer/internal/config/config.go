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

	"github.com/joho/godotenv"
)

// Environment variable names. These are the strings reported back to the
// operator when something is missing, so they are the single source of truth.
const (
	EnvPostgresDSN       = "POSTGRES_DSN"
	EnvAgentID           = "AGENT_ID"
	EnvOpenAIAPIKey      = "OPENAI_API_KEY"
	EnvAlchemyRPCURL     = "ALCHEMY_RPC_URL"
	EnvPrivateKey        = "PRIVATE_KEY"
	EnvAuditLogAddress   = "AUDIT_LOG_ADDRESS"
	EnvPunishmentAddress = "PUNISHMENT_ADDRESS"
	EnvLlamaGuardURL     = "LLAMA_GUARD_URL"
)

// Requirement sets per component. A process requires only what it actually
// uses, so the gateway does not demand chain credentials it never touches.
var (
	RequiredForSeeder   = []string{EnvPostgresDSN, EnvAgentID}
	RequiredForGateway  = []string{EnvPostgresDSN, EnvLlamaGuardURL}
	RequiredForChain    = []string{EnvAlchemyRPCURL, EnvPrivateKey, EnvAuditLogAddress, EnvPunishmentAddress}
	RequiredForOverseer = []string{EnvPostgresDSN, EnvAgentID, EnvOpenAIAPIKey}
)

// Config holds every value this project reads from the environment.
type Config struct {
	PostgresDSN       string
	AgentID           string
	OpenAIAPIKey      string
	AlchemyRPCURL     string
	PrivateKey        string
	AuditLogAddress   string
	PunishmentAddress string
	LlamaGuardURL     string
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
		EnvPostgresDSN:       &c.PostgresDSN,
		EnvAgentID:           &c.AgentID,
		EnvOpenAIAPIKey:      &c.OpenAIAPIKey,
		EnvAlchemyRPCURL:     &c.AlchemyRPCURL,
		EnvPrivateKey:        &c.PrivateKey,
		EnvAuditLogAddress:   &c.AuditLogAddress,
		EnvPunishmentAddress: &c.PunishmentAddress,
		EnvLlamaGuardURL:     &c.LlamaGuardURL,
	}
}

func loadFrom(get getenv) Config {
	var c Config
	for key, field := range c.fields() {
		*field = strings.TrimSpace(get(key))
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
