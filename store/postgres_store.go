// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package store

import (
	"database/sql"
	"log"
	"strings"

	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/util"
	_ "github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func (db *PostgresStore) CloseStore() {
	db.db.Close()
}

func (db *PostgresStore) AddUser(user *service.User) (string, bool, error) {
	insertStmt, err := db.db.Prepare("INSERT INTO user_v1 (username, password, roles, request_id) VALUES ($1, $2, $3, '');")
	if err != nil {
		log.Fatalf("Cannot create statement for AddUser: %s", err.Error())
		return user.Username, false, err
	}
	defer insertStmt.Close()

	_, err = insertStmt.Exec(user.Username, user.Password, util.EncodeRoles((user.Roles)))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return user.Username, false, nil
		}
		return user.Username, false, err
	}

	return user.Username, true, nil
}

func (db *PostgresStore) StoreUser(user *service.User) (string, error) {
	updateStmt, err := db.db.Prepare("UPDATE user_v1 SET password=$1, roles=$2, request_id=$3 WHERE username=$4;")
	if err != nil {
		log.Fatalf("Cannot create statement for StoreUser: %s", err.Error())
		return user.Username, err
	}
	defer updateStmt.Close()

	_, err = updateStmt.Exec(user.Password, util.EncodeRoles(user.Roles), user.RefreshToken, user.Username)
	if err != nil {
		log.Fatalf("Cannot execute statement for StoreUser: %s", err.Error())
		return user.Username, err
	}

	return user.Username, nil
}

func (db *PostgresStore) GetUser(username string) *service.User {
	var user service.User
	var roles string

	getUserStmt, err := db.db.Prepare("SELECT username, password, roles, request_id FROM user_v1 WHERE username=$1;")
	if err != nil {
		log.Fatalf("Cannot create statement for GetUser: %s", err.Error())
		return nil
	}
	defer getUserStmt.Close()

	err = getUserStmt.QueryRow(username).Scan(&user.Username, &user.Password, &roles, &user.RefreshToken)
	if err != nil {
		return nil
	}

	user.Roles = util.DecodeRoles(roles)
	return &user
}

func (db *PostgresStore) DeleteUser(user *service.User) error {
	deleteStmt, err := db.db.Prepare("DELETE FROM user_v1 WHERE username=$1;")
	if err != nil {
		log.Fatalf("Cannot create statement for DeleteUser: %s", err.Error())
		return nil
	}
	defer deleteStmt.Close()

	_, err = deleteStmt.Exec(user.Username)
	if err != nil {
		log.Fatalf("Cannot execute statement for DeleteUser: %s", err.Error())
		return nil
	}

	return err
}

func (db *PostgresStore) GetUsers() *[]service.User {
	getListStmt, err := db.db.Prepare("SELECT * FROM user_v1;")
	if err != nil {
		log.Fatalf("Cannot create statement for GetUsers: %s", err.Error())
		return nil
	}
	defer getListStmt.Close()

	var users []service.User
	rows, err := getListStmt.Query()
	defer rows.Close()
	if err != nil {
		log.Fatalf("Cannot execute statement for GetUsers: %s", err.Error())
		return nil
	}

	for rows.Next() {
		var current service.User
		var roles string
		if err := rows.Scan(&current.Username, &current.Password, &roles, &current.RefreshToken); err != nil {
			log.Fatalf("Cannot access rows for GetUsers: %s", err.Error())
			return nil
		}
		current.Roles = util.DecodeRoles(roles)
		users = append(users, current)
	}
	return &users
}

func (db *PostgresStore) RestoreUsers(users *[]service.User) error {
	tx, err := db.db.Begin()
	if err != nil {
		log.Fatalf("Cannot create transaction for RestoreUsers: %s", err.Error())
		return err
	}
	defer tx.Rollback()

	deleteAllStmt, err := db.db.Prepare("DELETE FROM user_v1;")
	if err != nil {
		log.Fatalf("Cannot create delete statement for RestoreUsers: %s", err.Error())
		return err
	}
	defer deleteAllStmt.Close()

	insertStmt, err := db.db.Prepare("INSERT INTO user_v1 (username, password, roles, request_id) VALUES ($1, $2, $3, '');")
	if err != nil {
		log.Fatalf("Cannot create insert statement for RestoreUser: %s", err.Error())
		return err
	}
	defer insertStmt.Close()

	_, err = deleteAllStmt.Exec()
	if err != nil {
		return err
	}
	for _, user := range *users {
		_, err = insertStmt.Exec(user.Username, user.Password, util.EncodeRoles(user.Roles))
		if err != nil {
			return err
		}
	}

	tx.Commit()
	return nil
}
