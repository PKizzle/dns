package dbsqlite

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

type Dbsqlite struct {
	db *sql.DB
}
