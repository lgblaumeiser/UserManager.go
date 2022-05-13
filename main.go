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

	rest "github.com/GIT_USER_ID/GIT_REPO_ID/rest"
)

func main() {
	log.Printf("Server started")

	InfrastructureApiService := rest.NewInfrastructureApiService()
	InfrastructureApiController := rest.NewInfrastructureApiController(InfrastructureApiService)

	UsersApiService := rest.NewUsersApiService()
	UsersApiController := rest.NewUsersApiController(UsersApiService)

	router := rest.NewRouter(InfrastructureApiController, UsersApiController)

	log.Fatal(http.ListenAndServe(":19749", router))
}
