package main

import (
	"database/sql"
	"log"

	ssa "github.com/hiddedorhout/ca_ssa/ssa"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := setupDb()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := ssa.NewSsaService(db); err != nil {
		log.Fatal(err)
	}
}

func setupDb() (db *sql.DB, err error) {
	return sql.Open("sqlite3", ":memory:")
}
