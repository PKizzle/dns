package dbsqlite

import (
	"github.com/jmoiron/sqlx"
)

func Select(db *sqlx.DB, query string, args ...any) ([]RR, error) {
	rrs := []RR{}

	if err := db.Select(&rrs, query, args...); err != nil {
		return nil, err
	}
	return rrs, nil
}
