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

// Package mysqlclient provides a reusable MySQL client for network service probing,
// password authentication, and sentinel error classification.
package mysqlclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"google.golang.org/protobuf/proto"

	mccpb "github.com/google/goonami-scanner/common/clients/mysqlclient/mysql_client_config_go_proto"
)

const (
	// DefaultTimeout is the default timeout for MySQL connections and authentication.
	DefaultTimeout = time.Duration(mccpb.Default_MySQLClientConfig_TimeoutSeconds) * time.Second
)

var (
	// ErrPasswordAuthUnsupported indicates the MySQL server does not support password
	// authentication or disallows connections from the scanner host.
	ErrPasswordAuthUnsupported = errors.New("mysql: password authentication unsupported")

	// ErrNotMySQLService indicates the target network service is not a valid MySQL service.
	ErrNotMySQLService = errors.New("mysql: target is not a MySQL service")

	// ErrAuthFailed indicates the credentials were rejected by the MySQL server.
	ErrAuthFailed = errors.New("mysql: authentication failed")
)

func init() {
	_ = mysql.SetLogger(&mysql.NopLogger{})
}

// Client manages MySQL connection establishment and password authentication.
type Client struct {
	coreConfig *config.Config
	config     *mccpb.MySQLClientConfig
}

// New creates a new MySQL Client populated from configuration.
func New(cfg *config.Config) *Client {
	mysqlCfg := &mccpb.MySQLClientConfig{}
	if cfg != nil {
		if cfg.ClientsConfig().HasMysql() {
			proto.Merge(mysqlCfg, cfg.ClientsConfig().GetMysql())
		}
		if !mysqlCfg.HasTimeoutSeconds() {
			if timeout := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); timeout > 0 {
				mysqlCfg.SetTimeoutSeconds(timeout)
			}
		}
	}

	return &Client{
		coreConfig: cfg,
		config:     mysqlCfg,
	}
}

// Timeout returns the configured connection and authentication timeout duration.
func (c *Client) Timeout() time.Duration {
	if c.config.GetTimeoutSeconds() > 0 {
		return time.Duration(c.config.GetTimeoutSeconds()) * time.Second
	}
	return DefaultTimeout
}

// Connect attempts MySQL password authentication with the given username and password.
// On success, it returns an established *sql.DB handle (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, or ErrNotMySQLService) wrapping the underlying MySQL error.
func (c *Client) Connect(ctx context.Context, addr, username, password string) (db *sql.DB, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	ctx = log.ContextForModule(ctx, "clients/mysqlclient")

	timeout := c.Timeout()
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	driverCfg := mysql.NewConfig()
	driverCfg.User = username
	driverCfg.Passwd = password
	driverCfg.Net = "tcp"
	driverCfg.Addr = addr
	driverCfg.Timeout = timeout
	driverCfg.ReadTimeout = timeout
	driverCfg.WriteTimeout = timeout
	driverCfg.AllowNativePasswords = true
	driverCfg.AllowCleartextPasswords = true
	driverCfg.AllowOldPasswords = true
	driverCfg.AllowFallbackToPlaintext = true
	driverCfg.Logger = &mysql.NopLogger{}

	connector, err := mysql.NewConnector(driverCfg)
	if err != nil {
		return nil, ClassifyError(err)
	}

	db = sql.OpenDB(connector)
	defer func() {
		if r := recover(); r != nil {
			_ = db.Close()
			db = nil
			err = fmt.Errorf("%w: malformed handshake packet (%v)", ErrNotMySQLService, r)
		}
	}()

	if err := db.PingContext(connCtx); err != nil {
		_ = db.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "MySQL connection/authentication to %s for user %q failed: %v", addr, username, err)
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrNotMySQLService, err)
		}
		return nil, ClassifyError(err)
	}
	return db, nil
}

// ClassifyError maps standard network and MySQL driver errors into canonical sentinels
// wrapping the original error.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrPasswordAuthUnsupported) || errors.Is(err, ErrNotMySQLService) {
		return err
	}

	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1044, 1045, 1698:
			return fmt.Errorf("%w: %w", ErrAuthFailed, err)
		case 1129, 1130, 1251, 1524:
			return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
		}
		if mysqlErr.SQLState == [5]byte{'2', '8', '0', '0', '0'} {
			return fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
	}

	if matchesAnyError(err, passwordAuthUnsupportedSentinels) {
		return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
	}

	if matchesAnyError(err, notMySQLServiceSentinels) {
		return fmt.Errorf("%w: %w", ErrNotMySQLService, err)
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "access denied") {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if containsAny(msg, passwordAuthUnsupportedSubstrings) {
		return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
	}
	if containsAny(msg, notMySQLServiceSubstrings) {
		return fmt.Errorf("%w: %w", ErrNotMySQLService, err)
	}

	return err
}

var (
	passwordAuthUnsupportedSentinels = []error{
		mysql.ErrUnknownPlugin,
		mysql.ErrCleartextPassword,
		mysql.ErrNativePassword,
		mysql.ErrOldPassword,
	}
	notMySQLServiceSentinels = []error{
		mysql.ErrMalformPkt,
		mysql.ErrOldProtocol,
		mysql.ErrInvalidConn,
		mysql.ErrPktSync,
		mysql.ErrPktSyncMul,
		mysql.ErrNoTLS,
		io.EOF,
		io.ErrUnexpectedEOF,
	}
	passwordAuthUnsupportedSubstrings = []string{
		"is not allowed to connect",
		"blocked because of many connection errors",
		"authentication plugin is not supported",
	}
	notMySQLServiceSubstrings = []string{
		"malformed packet",
		"bad connection",
		"invalid connection",
		"unsupported protocol version",
		"protocol 41+",
		"commands out of sync",
		"connection refused",
		"no route to host",
		"connection reset",
		"i/o timeout",
		"eof",
	}
)

func matchesAnyError(err error, targets []error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
