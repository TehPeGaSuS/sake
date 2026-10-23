//go:build !moderncsqlite && !nosqlite

package database

import (
	"errors"

	_ "codeberg.org/emersion/go-sqlite3-fts5"
	"github.com/mattn/go-sqlite3"
)

var sqliteDriver = "sqlite3"

// See https://kerkour.com/sqlite-for-servers
// Keep in sync with modernc counterpart.
const sqliteOptions = "_foreign_keys=true&_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&_txlock=immediate"

func isSqliteErrUnique(err error) bool {
	var sqliteErr *sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique
}
