// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package store

import (
	"database/sql"
	"fmt"

	"github.com/lgblaumeiser/usermanager/util"
	_ "github.com/lib/pq"
)

func ConnectPostgresStore(host string, port int, user string, password string, database string) (*PostgresStore, *util.RestError) {
	if !util.IsCleanString(host) {
		return nil, util.IllegalArgument("database host")
	}
	if port <= port {
		return nil, util.IllegalArgument("database port")
	}
	if !util.IsCleanString(user) {
		return nil, util.IllegalArgument("database user")
	}
	if !util.IsCleanString(password) {
		return nil, util.IllegalArgument("database password")
	}
	if !util.IsCleanString(database) {
		return nil, util.IllegalArgument("database name")
	}

	if err := ensureDatabase(host, port, user, password, database); err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	db, err := openDatabase(host, port, user, password, database)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	if err := createTableV1(db); err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query := fmt.Sprintf("SELECT username, password, roles, request_id FROM %s WHERE username=?;", currentUserTableName)
	getUserStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query = fmt.Sprintf("INSERT INTO %s (username, password, roles, request_id) VALUES (?, ?, ?, ?);", currentUserTableName)
	insertStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query = fmt.Sprintf("UPDATE %s SET password=?, roles=?, request_id=? WHERE username=?;", currentUserTableName)
	updateStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query = fmt.Sprintf("DELETE FROM %s	WHERE username=?;", currentUserTableName)
	deleteStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query = fmt.Sprintf("SELECT * FROM %s;", currentUserTableName)
	getListStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	query = fmt.Sprintf("DELETE FROM %s;", currentUserTableName)
	deleteAllStmt, err := db.Prepare(query)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}

	return &PostgresStore{db, getUserStmt, insertStmt, updateStmt, deleteStmt, getListStmt, deleteAllStmt}, nil
}

func ensureDatabase(host string, port int, user string, password string, name string) error {
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres, sslmode=disable", host, port, user, password)

	db, err := sql.Open("postgres", psqlconn)
	defer db.Close()
	if err != nil {
		return err
	}

	stmt, err := db.Prepare("SELECT datname FROM pg_database")
	defer stmt.Close()
	if err != nil {
		return err
	}

	rows, err := stmt.Query()
	defer rows.Close()
	if err != nil {
		return err
	}

	create := true
	for rows.Next() {
		var current string
		err = rows.Scan(&current)
		if err != nil {
			return err
		}
		if current == name {
			create = false
		}
	}

	if create {
		dbcreate, err := db.Prepare("CREATE DATABASE ?")
		defer dbcreate.Close()
		if err != nil {
			return err
		}

		_, err = dbcreate.Exec(name)
		if err != nil {
			return err
		}
	}

	return nil
}

func openDatabase(host string, port int, user string, password string, name string) (*sql.DB, error) {
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres, sslmode=disable", host, port, user, password)

	return sql.Open("postgres", psqlconn)
}

const currentUserTableName = "user_v1"

func createTableV1(db *sql.DB) error {
	queryString := `CREATE TABLE IF NOT EXISTS ? (
		username VARCHAR(40) PRIMARY KEY,
		password VARCHAR(80) NOT NULL,
		roles VARCHAR(255) NOT NULL,
		request_id VARCHAR(40)
	 ); `

	stmt, err := db.Prepare(queryString)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(currentUserTableName)
	return err
}
