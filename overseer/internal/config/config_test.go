package config

import (
	"strings"
	"testing"
)

func fullEnv() map[string]string {
	return map[string]string{
		EnvPostgresDSN:       "postgres://localhost/openclaw",
		EnvAgentID:           "agent-1",
		EnvOpenAIAPIKey:      "sk-test",
		EnvAlchemyRPCURL:     "https://example.invalid/rpc",
		EnvPrivateKey:        "0xabc",
		EnvAuditLogAddress:   "0x0000000000000000000000000000000000000001",
		EnvPunishmentAddress: "0x0000000000000000000000000000000000000002",
		EnvLlamaGuardURL:     "http://localhost:8000",
	}
}

func fakeGetenv(env map[string]string) getenv {
	return func(k string) string { return env[k] }
}

var allRequirementSets = map[string][]string{
	"seeder":   RequiredForSeeder,
	"gateway":  RequiredForGateway,
	"chain":    RequiredForChain,
	"overseer": RequiredForOverseer,
}

func TestRequire_PassesWhenEverythingIsSet(t *testing.T) {
	c := loadFrom(fakeGetenv(fullEnv()))
	for name, keys := range allRequirementSets {
		if err := c.Require(keys...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each missing variable must be named in the error. An operator should not have
// to read the source to find out which one they forgot.
func TestRequire_NamesEachMissingVariable(t *testing.T) {
	for name, keys := range allRequirementSets {
		for _, missing := range keys {
			env := fullEnv()
			delete(env, missing)

			err := loadFrom(fakeGetenv(env)).Require(keys...)
			if err == nil {
				t.Errorf("%s: missing %s produced no error", name, missing)
				continue
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("%s: error %q does not name %s", name, err, missing)
			}
		}
	}
}

// All of them at once should be reported together, not one per restart.
func TestRequire_ReportsEveryMissingVariableAtOnce(t *testing.T) {
	err := loadFrom(fakeGetenv(map[string]string{})).Require(RequiredForChain...)
	if err == nil {
		t.Fatal("empty environment produced no error")
	}
	for _, key := range RequiredForChain {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q omits %s", err, key)
		}
	}
}

// A variable set to whitespace is not set.
func TestRequire_TreatsBlankAsMissing(t *testing.T) {
	env := fullEnv()
	env[EnvPostgresDSN] = "   "

	err := loadFrom(fakeGetenv(env)).Require(EnvPostgresDSN)
	if err == nil {
		t.Fatal("a whitespace-only value was accepted")
	}
	if !strings.Contains(err.Error(), EnvPostgresDSN) {
		t.Errorf("error %q does not name %s", err, EnvPostgresDSN)
	}
}

func TestLoad_TrimsSurroundingWhitespace(t *testing.T) {
	env := fullEnv()
	env[EnvAgentID] = "  agent-1\n"

	if got := loadFrom(fakeGetenv(env)).AgentID; got != "agent-1" {
		t.Errorf("AgentID = %q, want %q", got, "agent-1")
	}
}

// A requirement set that names a variable this package does not know about is
// a typo, and the one thing it must not do is quietly satisfy itself.
func TestRequire_UnknownKeyIsReportedMissing(t *testing.T) {
	err := loadFrom(fakeGetenv(fullEnv())).Require("POSTGRES_DNS")
	if err == nil {
		t.Fatal("an unrecognised variable name was accepted")
	}
	if !strings.Contains(err.Error(), "POSTGRES_DNS") {
		t.Errorf("error %q does not name the unrecognised variable", err)
	}
}
