/*
 * User Manager API
 *
 * Description of a user manager API
 *
 * API version: 1.0.0
 * Contact: lars@lgblaumeiser.de
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */
package rest

import (
	"net/http"
)

// InfrastructureApiRouter defines the required methods for binding the api requests to a responses for the InfrastructureApi
// The InfrastructureApiRouter implementation should parse necessary information from the http request,
// pass the data to a InfrastructureApiServicer to perform the required actions, then write the service results to the http response.
type InfrastructureApiRouter interface {
	Backup(http.ResponseWriter, *http.Request)
	License(http.ResponseWriter, *http.Request)
	Restore(http.ResponseWriter, *http.Request)
}

// UsersApiRouter defines the required methods for binding the api requests to a responses for the UsersApi
// The UsersApiRouter implementation should parse necessary information from the http request,
// pass the data to a UsersApiServicer to perform the required actions, then write the service results to the http response.
type UsersApiRouter interface {
	AuthenticateUser(http.ResponseWriter, *http.Request)
	ChangePassword(http.ResponseWriter, *http.Request)
	ChangeRoles(http.ResponseWriter, *http.Request)
	DeleteUser(http.ResponseWriter, *http.Request)
	RegisterUser(http.ResponseWriter, *http.Request)
}
