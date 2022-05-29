/*
 * User Manager API
 *
 * Description of a user manager API
 *
 * API version: 1.0.0
 * Contact: lars@lgblaumeiser.de
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */
// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lgblaumeiser/usermanager/statik"
	"github.com/lgblaumeiser/usermanager/util"
	"github.com/rakyll/statik/fs"

	"github.com/lgblaumeiser/usermanager/rest"
	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/store"
)

func main() {
	log.Printf("Server started")

	var srvport int

	var dbhost string
	var dbport int
	var dbuser string
	var dbpawd string
	var dbname string

	flag.IntVar(&srvport, "srvport", 8080, "service port")
	flag.StringVar(&dbhost, "dbhost", "", "database hostname")
	flag.IntVar(&dbport, "dbport", -1, "database port")
	flag.StringVar(&dbuser, "dbuser", "", "database username")
	flag.StringVar(&dbpawd, "dbpwd", "", "database user password")
	flag.StringVar(&dbname, "dbname", "", "database name")
	flag.Parse()

	var database service.UserStore
	var rerr *util.RestError
	if dbport == -1 {
		database, rerr = store.ConnectPostgresStore(dbhost, dbport, dbuser, dbpawd, dbname)
		if rerr != nil {
			panic(rerr)
		}
	} else {
		database = store.CreateMemoryStore()
	}
	defer database.CloseStore()

	userService, rerr := service.NewUserService(database)
	if rerr != nil {
		panic(rerr)
	}

	InfrastructureApiController := rest.NewInfrastructureApiController(&userService)
	UsersApiController := rest.NewUsersApiController(&userService)

	router := rest.NewRouter(InfrastructureApiController, UsersApiController)

	statikFS, err := fs.New()
	if err != nil {
		panic(err)
	}

	staticServer := http.FileServer(statikFS)
	sh := http.StripPrefix("/openapi/", staticServer)
	router.PathPrefix("/openapi/").Handler(sh)

	portstring := fmt.Sprintf(":%d", srvport)
	log.Fatal(http.ListenAndServe(portstring, router))
}
