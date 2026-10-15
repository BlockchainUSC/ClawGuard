// Command migrate applies pending database migrations.
//
//	go run ./overseer/cmd/migrate            # apply anything outstanding
//	go run ./overseer/cmd/migrate -dry-run   # list what would be applied
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/guard/overseer/internal/config"
	"openclaw/guard/overseer/internal/migrate"
)

func main() {
	dir := flag.String("dir", "migrations", "directory holding the .sql files")
	dryRun := flag.Bool("dry-run", false, "list pending migrations without applying them")
	flag.Parse()

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

	if *dryRun {
		pending, err := migrate.Pending(ctx, pool, *dir)
		if err != nil {
			log.Fatal(err)
		}
		if len(pending) == 0 {
			fmt.Println("up to date")
			return
		}
		for _, v := range pending {
			fmt.Printf("pending: %s\n", v)
		}
		os.Exit(1) // non-zero so CI can gate on "schema is current"
	}

	applied, err := migrate.Apply(ctx, pool, *dir)
	if err != nil {
		log.Fatal(err)
	}
	if len(applied) == 0 {
		fmt.Println("up to date")
		return
	}
	for _, v := range applied {
		fmt.Printf("applied: %s\n", v)
	}
}
