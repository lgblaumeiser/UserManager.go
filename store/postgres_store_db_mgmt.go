// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package store

import (
	"database/sql"
	"fmt"

	"github.com/lgblaumeiser/usermanager/util"
	_ "github.com/lib/pq"
)

func ConnectPostgresStore(host string, port int, user string, password string, database string) *PostgresStore {
	if !util.IsCleanString(host) {
		panic("database host")
	}
	if port <= 0 {
		panic("database port")
	}
	if !util.IsCleanString(user) {
		panic("database user")
	}
	if !util.IsCleanString(password) {
		panic("database password")
	}
	if !util.IsCleanString(database) {
		panic("database name")
	}

	ensureDatabase(host, port, user, password, database)
	db := openDatabase(host, port, user, password, database)
	createTable(db)

	return &PostgresStore{db}
}

func ensureDatabase(host string, port int, user string, password string, name string) {
	db := openDatabase(host, port, user, password, "postgres")
	defer db.Close()

	stmt, err := db.Prepare("SELECT datname FROM pg_database;")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	create := true
	for rows.Next() {
		var current string
		err = rows.Scan(&current)
		if err != nil {
			panic(err)
		}
		if current == name {
			create = false
		}
	}

	if create {
		dbcreate, err := db.Prepare(fmt.Sprintf("CREATE DATABASE %s;", name))
		if err != nil {
			panic(err)
		}
		defer dbcreate.Close()

		_, err = dbcreate.Exec()
		if err != nil {
			panic(err)
		}
	}
}

func openDatabase(host string, port int, user string, password string, name string) *sql.DB {
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, name)

	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		panic(err)
	}
	return db
}

const currentUserTableName = "user_v1"

func createTable(db *sql.DB) {
	stmt, err := db.Prepare(fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s (username VARCHAR(40) PRIMARY KEY, password VARCHAR(80) NOT NULL, "+
			"roles VARCHAR(255) NOT NULL, request_id VARCHAR(40));", currentUserTableName))
	if err != nil {
		panic(err)
	}

	_, err = stmt.Exec()
	if err != nil {
		panic(err)
	}
}
