// Command reset-user clears a user's accumulated risk and restores full
// capability to their recent sessions.
//
//	go run ./overseer/cmd/reset-user -user alice
//
// This is the escape hatch for a false positive. Nothing on the request path
// can lower a tier; if the guard demotes someone it should not have, this is
// how a human undoes it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/oversight/overseer/internal/config"
	"openclaw/oversight/overseer/internal/session"
)

func main() {
	user := flag.String("user", "", "the user_id to reset (required)")
	flag.Parse()

	if *user == "" {
		flag.Usage()
		log.Fatal("-user is required")
	}

	cfg := config.Load()
	if err := cfg.Require(config.EnvPostgresDSN); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("connecting: %v", err)
	}
	defer pool.Close()

	n, err := session.NewPostgresStore(pool).ResetUser(ctx, *user)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reset %d session(s) for %q\n", n, *user)
}
