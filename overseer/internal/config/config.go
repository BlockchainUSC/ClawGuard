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
	RequiredForSeeder  = []string{EnvPostgresDSN, EnvAgentID}
	RequiredForGateway = []string{EnvPostgresDSN, EnvLlamaGuardURL}
	RequiredForChain   = []string{EnvAlchemyRPCURL, EnvPrivateKey, EnvAuditLogAddress, EnvPunishmentAddress}
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
	_ = godotenv.Load()
	return loadFrom(osGetenv)
}

func loadFrom(get getenv) Config {
	return Config{
		PostgresDSN:       strings.TrimSpace(get(EnvPostgresDSN)),
		AgentID:           strings.TrimSpace(get(EnvAgentID)),
		OpenAIAPIKey:      strings.TrimSpace(get(EnvOpenAIAPIKey)),
		AlchemyRPCURL:     strings.TrimSpace(get(EnvAlchemyRPCURL)),
		PrivateKey:        strings.TrimSpace(get(EnvPrivateKey)),
		AuditLogAddress:   strings.TrimSpace(get(EnvAuditLogAddress)),
		PunishmentAddress: strings.TrimSpace(get(EnvPunishmentAddress)),
		LlamaGuardURL:     strings.TrimSpace(get(EnvLlamaGuardURL)),
	}
}

// Require reports every requested variable that is empty, naming each one.
func (c Config) Require(keys ...string) error {
	var missing []string
	for _, k := range keys {
		if c.lookup(k) == "" {
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

func (c Config) lookup(key string) string {
	switch key {
	case EnvPostgresDSN:
		return c.PostgresDSN
	case EnvAgentID:
		return c.AgentID
	case EnvOpenAIAPIKey:
		return c.OpenAIAPIKey
	case EnvAlchemyRPCURL:
		return c.AlchemyRPCURL
	case EnvPrivateKey:
		return c.PrivateKey
	case EnvAuditLogAddress:
		return c.AuditLogAddress
	case EnvPunishmentAddress:
		return c.PunishmentAddress
	case EnvLlamaGuardURL:
		return c.LlamaGuardURL
	default:
		return ""
	}
}

func pluralise(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
