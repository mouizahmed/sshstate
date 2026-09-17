// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mouizahmed/sshstate/internal/buildinfo"
	"github.com/mouizahmed/sshstate/internal/relay"
)

const usage = `sshstate-server - sshstate sync relay

usage: sshstate-server <command> [flags]

commands:
  serve      run the HTTP relay
  version    print version

serve flags:
  -addr string
        listen address (default ":8080")
  -data string
        database path (default "/var/lib/sshstate/relay.db")
  -bootstrap-secret string
        path to the operator-mounted one-time secret file
  -public-http
        clients reach this relay over plain HTTP (development only)

The relay terminates plain HTTP and expects an HTTPS reverse proxy in front of
it. -public-http describes the URL clients use, not this process's listener:
behind a terminating proxy the public URL is still https, so leave it unset.
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("sshstate-server: ")

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch cmd := flag.Arg(0); cmd {
	case "serve":
		if err := serve(flag.Args()[1:]); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Printf("sshstate-server %s\n", buildinfo.String())
		fmt.Println()
		fmt.Println(buildinfo.Notice())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "sshstate-server: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	addr := fs.String("addr", ":8080", "listen address")
	data := fs.String("data", "/var/lib/sshstate/relay.db", "database path")
	secretPath := fs.String("bootstrap-secret", "", "path to the one-time bootstrap secret file")
	publicHTTP := fs.Bool("public-http", false, "clients reach this relay over plain HTTP")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := relay.Open(*data)
	if err != nil {
		return err
	}
	defer store.Close()

	cfg := relay.Config{PublicHTTPS: !*publicHTTP}
	status, err := store.ConfigureBootstrap(*secretPath)
	if err != nil {
		return err
	}
	log.Print(status)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           relay.NewServer(store, cfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.Default(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		log.Printf("listening on %s, database %s", *addr, store.Path())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		log.Printf("shutting down")
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
		return <-errs
	}
}
