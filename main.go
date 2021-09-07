package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	sm "github.com/hiddedorhout/ca_ssa/session"
	ssa "github.com/hiddedorhout/ca_ssa/ssa"
	_ "github.com/mattn/go-sqlite3"
)

var baseUrl string
var port string

func init() {
	baseUrl = "http://localhost"
	port = "3000"
}

func main() {
	db, err := setupDb()
	if err != nil {
		log.Fatal(err)
	}

	var sms sm.SessionManagement
	sessionManagementService, err := sm.CreateSessionService(db)
	if err != nil {
		log.Fatal(err)
	}

	sms = sessionManagementService

	ssaService, err := ssa.NewSsaService(db, sms, baseUrl, port)
	if err != nil {
		log.Fatal(err)
	}

	ssaService.SetupRoutes()

	log.Println(fmt.Sprintf("CA Server running on: %s", port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))

}

func setupDb() (db *sql.DB, err error) {
	return sql.Open("sqlite3", "test.db")
}
