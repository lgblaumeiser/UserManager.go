// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package store

import (
	"database/sql"

	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/util"
	_ "github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB

	getUserStmt   *sql.Stmt
	insertStmt    *sql.Stmt
	updateStmt    *sql.Stmt
	deleteStmt    *sql.Stmt
	getListStmt   *sql.Stmt
	deleteAllStmt *sql.Stmt
}

func (db *PostgresStore) CloseStore() {
	db.deleteAllStmt.Close()
	db.getListStmt.Close()
	db.deleteStmt.Close()
	db.updateStmt.Close()
	db.insertStmt.Close()
	db.getUserStmt.Close()
	db.db.Close()
}

func (db *PostgresStore) AddUser(user *service.User) (string, bool, error) {
	result, err := db.insertStmt.Exec(user.Username, user.Password, util.EncodeRoles(user.Roles), "")
	ar, _ := result.RowsAffected()
	success := ar == 1
	return user.Username, success, err
}

func (db *PostgresStore) StoreUser(user *service.User) (string, error) {
	_, err := db.updateStmt.Exec(user.Password, util.EncodeRoles(user.Roles), user.RefreshToken, user.Username)
	return user.Username, err
}

func (db *PostgresStore) GetUser(username string) *service.User {
	var user service.User
	var roles string
	err := db.getUserStmt.QueryRow(username).Scan(&user.Username, &user.Password, &roles, &user.RefreshToken)
	if err != nil {
		return nil
	}
	user.Roles = util.DecodeRoles(roles)
	return &user
}

func (db *PostgresStore) DeleteUser(user *service.User) error {
	_, err := db.deleteStmt.Exec(user.Username)
	return err
}

func (db *PostgresStore) GetUsers() *[]service.User {
	var users []service.User
	rows, err := db.getListStmt.Query()
	defer rows.Close()
	if err != nil {
		return nil
	}
	for rows.Next() {
		var current service.User
		var roles string
		if err := rows.Scan(&current.Username, &current.Password, &roles, &current.RefreshToken); err != nil {
			return nil
		}
		current.Roles = util.DecodeRoles(roles)
		users = append(users, current)
	}
	return &users
}

func (db *PostgresStore) RestoreUsers(users *[]service.User) error {
	var encounteredError error = nil
	_, err := db.deleteAllStmt.Exec()
	if err != nil && encounteredError != nil {
		encounteredError = err
	}
	for _, user := range *users {
		_, err = db.insertStmt.Exec(user.Username, user.Password, util.EncodeRoles(user.Roles), "")
		if err != nil && encounteredError != nil {
			encounteredError = err
		}
	}
	return encounteredError
}
