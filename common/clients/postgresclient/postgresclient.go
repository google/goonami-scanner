/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package postgresclient provides a shared PostgreSQL client wrapper around database/sql and lib/pq.
package postgresclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	pgcfgpb "github.com/google/goonami-scanner/common/clients/postgresclient/postgres_client_config_go_proto"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/lib/pq"
)

const (
	// DefaultDatabase is the default PostgreSQL database used when none is specified.
	DefaultDatabase = "postgres"

	defaultTimeoutSeconds = 5
)

var (
	// ErrAuthFailed indicates the PostgreSQL server rejected the provided credentials.
	ErrAuthFailed = errors.New("PostgreSQL authentication failed")

	// ErrPasswordAuthUnsupported indicates the PostgreSQL server does not support password
	// authentication for the connection or requested an unsupported authentication mechanism.
	ErrPasswordAuthUnsupported = errors.New("PostgreSQL server does not support password authentication for this connection")

	// ErrNotPostgresService indicates the target did not respond as a valid PostgreSQL service
	// or could not be reached.
	ErrNotPostgresService = errors.New("target is not a reachable PostgreSQL service")
)

// Client is a PostgreSQL client configured from Goonami's configuration.
type Client struct {
	cfg *pgcfgpb.PostgresClientConfig
}

// New creates a new PostgreSQL client using settings from cfg.
func New(cfg *config.Config) *Client {
	clientCfg := pgcfgpb.PostgresClientConfig_builder{}.Build()
	if cfg != nil && cfg.ClientsConfig() != nil && cfg.ClientsConfig().HasPostgres() {
		clientCfg = cfg.ClientsConfig().GetPostgres()
	}
	return &Client{
		cfg: clientCfg,
	}
}

// Timeout returns the configured connection and authentication timeout.
func (c *Client) Timeout() time.Duration {
	secs := c.cfg.GetTimeoutSeconds()
	if secs <= 0 {
		secs = defaultTimeoutSeconds
	}
	return time.Duration(secs) * time.Second
}

// Connect opens and verifies a PostgreSQL connection to addr ("host:port") using the given
// credentials and database name (defaulting to DefaultDatabase when database is empty).
// On success, the caller is responsible for closing the returned *sql.DB.
func (c *Client) Connect(ctx context.Context, addr, username, password, database string) (db *sql.DB, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			db = nil
			err = fmt.Errorf("%w: driver panic: %v", ErrNotPostgresService, r)
		}
	}()

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || host == "" || port == "" {
		return nil, fmt.Errorf("%w: invalid address %q", ErrNotPostgresService, addr)
	}

	if database == "" {
		database = DefaultDatabase
	}

	timeout := c.Timeout()
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=prefer connect_timeout=%d",
		quoteDSNValue(host),
		quoteDSNValue(port),
		quoteDSNValue(username),
		quoteDSNValue(password),
		quoteDSNValue(database),
		timeoutSec,
	)

	connector, connErr := pq.NewConnector(dsn)
	if connErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotPostgresService, connErr)
	}

	rawDB := sql.OpenDB(connector)
	rawDB.SetMaxOpenConns(1)
	rawDB.SetMaxIdleConns(1)

	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	log.DebugContextf(connCtx, log.DebugLevelRequest, "Connecting to PostgreSQL at %s as %q (db=%q)", addr, username, database)

	if pingErr := rawDB.PingContext(connCtx); pingErr != nil {
		_ = rawDB.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(pingErr, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrNotPostgresService, pingErr)
		}
		return nil, ClassifyError(pingErr)
	}

	return rawDB, nil
}

// quoteDSNValue escapes single quotes and backslashes for a lib/pq keyword=value connection string.
func quoteDSNValue(v string) string {
	escaped := strings.ReplaceAll(v, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

// ClassifyError maps a PostgreSQL driver or network error to a sentinel error when applicable.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrPasswordAuthUnsupported) || errors.Is(err, ErrNotPostgresService) {
		return err
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "28P01":
			return fmt.Errorf("%w: %w", ErrAuthFailed, err)
		case "28000":
			if strings.Contains(strings.ToLower(pqErr.Message), "no pg_hba.conf entry") {
				return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
			}
			return fmt.Errorf("%w: %w", ErrAuthFailed, err)
		case "08P01":
			return fmt.Errorf("%w: %w", ErrNotPostgresService, err)
		case "0A000":
			return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
		}
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrNotPostgresService, err)
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unsupported authentication"),
		strings.Contains(msg, "kerberos error"),
		strings.Contains(msg, "no pg_hba.conf entry"):
		return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
	case strings.Contains(msg, "password authentication failed"),
		strings.Contains(msg, "scram-sha-256 error"):
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	case isNetworkOrProtocolError(msg):
		return fmt.Errorf("%w: %w", ErrNotPostgresService, err)
	}

	return err
}

func isNetworkOrProtocolError(lowerMsg string) bool {
	indicators := []string{
		"connection refused",
		"no route to host",
		"network is unreachable",
		"connection reset",
		"broken pipe",
		"i/o timeout",
		"eof",
		"unknown response for sslrequest",
		"unknown response for startup",
		"unexpected password response",
		"unexpected authentication response",
		"protocol version",
		"server error:",
		"ssl is not enabled",
		"tls:",
		"bad connection",
		"invalid connection",
	}
	for _, ind := range indicators {
		if strings.Contains(lowerMsg, ind) {
			return true
		}
	}
	return false
}
