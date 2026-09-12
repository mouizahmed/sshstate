// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/mouizahmed/sshstate/internal/activation"
	"github.com/mouizahmed/sshstate/internal/agentsrv"
	"github.com/mouizahmed/sshstate/internal/control"
	"github.com/mouizahmed/sshstate/internal/paths"
	"github.com/mouizahmed/sshstate/internal/peercred"
	"github.com/mouizahmed/sshstate/internal/vault"
)

const socketPerm os.FileMode = 0o600

type Daemon struct {
	mgr    *vault.Manager
	layout paths.Layout
	agent  *agentsrv.Agent
	log    *slog.Logger

	stopOnce sync.Once
	stop     chan struct{}
}

func New(mgr *vault.Manager, layout paths.Layout, log *slog.Logger) *Daemon {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Daemon{
		mgr:    mgr,
		layout: layout,
		agent:  agentsrv.New(mgr),
		log:    log,
		stop:   make(chan struct{}),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	release, err := AcquireInstanceLock(d.layout.DaemonLock())
	if err != nil {
		return err
	}
	defer release()

	controlLn, controlSrc, err := d.listen(activation.NameControl, d.layout.ControlSocket())
	if err != nil {
		return err
	}
	defer controlLn.Close()

	agentLn, agentSrc, err := d.listen(activation.NameAgent, d.layout.AgentSocket())
	if err != nil {
		controlLn.Close()
		return err
	}
	defer agentLn.Close()

	d.log.Info("daemon listening",
		"control", d.layout.ControlSocket(), "control_source", controlSrc,
		"agent", d.layout.AgentSocket(), "agent_source", agentSrc)

	srv := &http.Server{
		Handler:           d.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		ErrorLog:          slog.NewLogLogger(d.log.Handler(), slog.LevelDebug),
	}

	errc := make(chan error, 2)
	go func() {
		err := srv.Serve(guard(controlLn, d.log))
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("control socket: %w", err)
			return
		}
		errc <- nil
	}()
	go func() { errc <- d.serveAgent(agentLn) }()

	select {
	case <-ctx.Done():
	case <-d.stop:
	case err := <-errc:
		if err != nil {
			d.shutdown(srv, agentLn)
			return err
		}
	}
	d.shutdown(srv, agentLn)
	return nil
}

func (d *Daemon) shutdown(srv *http.Server, agentLn net.Listener) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = agentLn.Close()
	d.mgr.Lock()
	d.agent.Forget()
}

func (d *Daemon) Shutdown() {
	d.stopOnce.Do(func() { close(d.stop) })
}

func (d *Daemon) serveAgent(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("agent socket: %w", err)
		}
		if err := peercred.Check(conn); err != nil {
			d.log.Warn("rejected agent connection", "reason", err)
			conn.Close()
			continue
		}
		go func() {
			defer conn.Close()
			if err := agent.ServeAgent(d.agent, conn); err != nil && !errors.Is(err, os.ErrClosed) {
				d.log.Debug("agent connection ended", "reason", err)
			}
		}()
	}
}

func (d *Daemon) Agent() *agentsrv.Agent { return d.agent }

func (d *Daemon) listen(name, path string) (net.Listener, string, error) {
	ln, err := activation.Listener(name)
	switch {
	case err == nil:
		return ln, "activation", nil
	case errors.Is(err, activation.ErrNotActivated):
	default:
		return nil, "", fmt.Errorf("socket %q: %w", name, err)
	}
	ln, err = listenUnix(path)
	if err != nil {
		return nil, "", err
	}
	return ln, "foreground", nil
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, socketPerm); err != nil {
		ln.Close()
		return nil, fmt.Errorf("secure socket %s: %w", path, err)
	}
	return ln, nil
}

func guard(ln net.Listener, log *slog.Logger) net.Listener {
	return &guardedListener{Listener: ln, log: log}
}

type guardedListener struct {
	net.Listener
	log *slog.Logger
}

func (g *guardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := peercred.Check(conn); err != nil {
			g.log.Warn("rejected control connection", "reason", err)
			conn.Close()
			continue
		}
		return conn, nil
	}
}

var _ = control.APIVersion
