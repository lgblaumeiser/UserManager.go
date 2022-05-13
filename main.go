/*
 * User Manager API
 *
 * Description of a user manager API
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */
package main

import (
	"log"
	"net/http"

	_ "github.com/lgblaumeiser/usermanager/statik"
	"github.com/rakyll/statik/fs"

	rest "github.com/lgblaumeiser/usermanager/rest"
	service "github.com/lgblaumeiser/usermanager/service"
	store "github.com/lgblaumeiser/usermanager/store"
)

func main() {
	log.Printf("Server started")

	InfrastructureApiService := rest.NewInfrastructureApiService()
	InfrastructureApiController := rest.NewInfrastructureApiController(InfrastructureApiService)

	UsersApiService := rest.NewUsersApiService()
	UsersApiController := rest.NewUsersApiController(UsersApiService)

	router := rest.NewRouter(InfrastructureApiController, UsersApiController)

	statikFS, err := fs.New()
	if err != nil {
		panic(err)
	}

	staticServer := http.FileServer(statikFS)
	sh := http.StripPrefix("/openapi/", staticServer)
	router.PathPrefix("/openapi/").Handler(sh)

	store := store.CreateMemoryStore()

	service.InitializeUserService(store)

	log.Fatal(http.ListenAndServe(":19749", router))
}
