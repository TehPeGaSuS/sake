//go:build moderncsqlite && !nosqlite

package database

import (
	"errors"

	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

var sqliteDriver = "sqlite"

// Keep in sync with mattn counterpart.
const sqliteOptions = "_pragma=foreign_keys(true)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"

func isSqliteErrUnique(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	// TODO: check extended error code (requires upstream patch)
	return sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT
}
