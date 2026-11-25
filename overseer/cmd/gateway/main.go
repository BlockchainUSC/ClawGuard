// Command gateway runs the guardrail reverse proxy.
//
//	go run ./overseer/cmd/gateway
//
// Phase 3 forwards every request unmodified. The capability model is loaded,
// the session is tracked and the inspection seam runs, but nothing is stripped,
// routed or demoted yet.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/guard/overseer/internal/auth"
	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/config"
	"openclaw/guard/overseer/internal/gateway"
	"openclaw/guard/overseer/internal/inspect"
	"openclaw/guard/overseer/internal/session"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := config.Load()
	// Everything missing is reported at once, by name, before anything else is
	// attempted. Discovering a missing variable on the first request instead of
	// at boot is how a deploy looks healthy and is not.
	if err := cfg.Require(config.RequiredForGateway...); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pubKey, err := loadRSAPublicKey(cfg.JWTPublicKeyPath)
	if err != nil {
		return err
	}
	authenticator, err := auth.NewRSA(pubKey, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		return err
	}

	registry, err := gateway.LoadToolRegistry(cfg.ToolRegistryPath)
	if err != nil {
		// A bad registry fails the boot, not the first request: an
		// unclassified tool is a denied tool, so a typo here silently removes
		// capability from every session.
		return err
	}

	pool, err := pgxpool.New(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres unreachable: %w", err)
	}

	// Validated at startup rather than trusted. A zero-value Heuristics is not
	// inert — every threshold at zero means "entropy >= 0" and "spike >= 0" are
	// always true, so it fires on every request with weight zero: a noisy audit
	// trail that changes nothing, with nothing reporting a fault.
	heuristics := inspect.DefaultHeuristics()
	if err := heuristics.Validate(); err != nil {
		return err
	}

	// The semantic gate is registered only when a URL is configured, so the
	// gateway runs without a model present. A guardrail whose every path needs
	// a GPU does not get run.
	inspectors := []inspect.Registered{inspect.Enforcing(heuristics)}
	if cfg.LlamaGuardURL != "" {
		guard := inspect.LlamaGuard{
			BaseURL: cfg.LlamaGuardURL,
			Model:   cfg.LlamaGuardModel,
			Weight:  inspect.DefaultLlamaGuardWeight,
			// Its own client: the inspection budget is enforced by the runner's
			// context, and a transport-level timeout here would cut the request
			// before that deadline could report it as a floor.
			Client: &http.Client{},
		}

		// Load the model now, so the first user through the door is not the one
		// who pays the cold-start cost and gets floored for it. Not fatal: an
		// inference service that is not up yet is handled correctly at request
		// time, as a floor.
		warmCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		if err := guard.Warm(warmCtx); err != nil {
			log.Warn("could not warm the semantic gate", "err", err)
		} else {
			log.Info("semantic gate warm", "model", cfg.LlamaGuardModel)
		}
		cancel()

		inspectors = append(inspectors, inspect.Enforcing(guard))
	}

	g, err := gateway.New(gateway.Deps{
		Auth:     authenticator,
		Sessions: session.NewPostgresStore(pool),
		Registry: registry,
		Policy:   capability.DefaultPolicy(),
		Upstream: &gateway.Upstream{
			BaseURL: cfg.UpstreamBaseURL,
			APIKey:  cfg.UpstreamAPIKey,
			Client:  &http.Client{Timeout: cfg.UpstreamTimeout},
		},
		Log:           log,
		Inspectors:    inspectors,
		InspectBudget: cfg.InspectTimeout,

		// Detection ships before enforcement. The thresholds are placeholders
		// until an evaluation corpus can say what the false-positive rate is,
		// and a false positive restricts a real person. Decisions are computed
		// and logged; nothing is persisted or acted on.
		EnforceDecisions: false,

		// Off unless explicitly enabled. Capture stores prompts verbatim and
		// writes a row per inspector per request, which is the right trade only
		// while a corpus is being built.
		CaptureRawContent:   cfg.CaptureRawContent,
		RawContentRetention: cfg.RawContentRetention,
		// An inspector that cannot answer quarantines the request in hand.
		UnavailableFloor: capability.TierQuarantined,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           g.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			"addr", cfg.ListenAddr,
			"upstream", cfg.UpstreamBaseURL,
			"inspect_budget", cfg.InspectTimeout.String(),
			"inspectors", len(inspectors),
			"semantic_gate", cfg.LlamaGuardURL != "",
			"enforcement", "disabled: detection only until thresholds are calibrated",
			"capture", cfg.CaptureRawContent)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// loadRSAPublicKey reads a PEM public key. The gateway verifies tokens and
// never mints them, so it holds only the public half.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading JWT public key: %w", err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("JWT public key %s is not PEM encoded", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT public key %s: %w", path, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWT public key %s is %T, want RSA", path, parsed)
	}
	return pub, nil
}
