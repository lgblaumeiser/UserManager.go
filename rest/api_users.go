// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package rest

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	service "github.com/lgblaumeiser/usermanager/service"
)

type tokenResult struct {
	JwtToken string `json:"jwt_token,omitempty"`
}

type userId struct {
	UserId string `json:"userid,omitempty"`
}

// UsersApiController binds http requests to an api service and writes the service results to the http response
type UsersApiController struct {
	service service.UserService
}

// UsersApiOption for how the controller is set up.
type UsersApiOption func(*UsersApiController)

// NewUsersApiController creates a default api controller
func NewUsersApiController(s service.UserService, opts ...UsersApiOption) Router {
	controller := &UsersApiController{
		service: s,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all of the api route for the UsersApiController
func (c *UsersApiController) Routes() Routes {
	return Routes{
		{
			"AuthenticateUser",
			strings.ToUpper("Post"),
			"/users/authenticate",
			c.AuthenticateUser,
		},
		{
			"ChangePassword",
			strings.ToUpper("Put"),
			"/users",
			c.ChangePassword,
		},
		{
			"ChangeRoles",
			strings.ToUpper("Patch"),
			"/users",
			c.ChangeRoles,
		},
		{
			"DeleteUser",
			strings.ToUpper("Delete"),
			"/users",
			c.DeleteUser,
		},
		{
			"RegisterUser",
			strings.ToUpper("Post"),
			"/users",
			c.RegisterUser,
		},
	}
}

// AuthenticateUser - Authenticate a registered user by password, returns a jwt token
func (c *UsersApiController) AuthenticateUser(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)

	result := c.service.AuthenticateUser(userDataParam.Username, userDataParam.Password)

	if !handleError(result, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(tokenResult{result.Body}, http.StatusOK, w)
}

// ChangePassword - Change the password of the user, authentication provided either by token of user or of an admin
func (c *UsersApiController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	result := c.service.ChangePassword(userDataParam.Username, userDataParam.Password, requestor)

	if !handleError(result, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result.Body}, http.StatusOK, w)
}

// ChangeRoles - Change roles of user, admin roles can only be changed by an admin
func (c *UsersApiController) ChangeRoles(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	result := c.service.ChangeRoles(userDataParam.Username, requestor, &userDataParam.Newroles, &userDataParam.Obsroles)

	if !handleError(result, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result.Body}, http.StatusOK, w)
}

// DeleteUser - Delete a user and all its data from the database
func (c *UsersApiController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	result := c.service.DeleteUser(userDataParam.Username, requestor)

	if !handleError(result, w, r.RequestURI) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegisterUser - Register a new user, needs no authentication
func (c *UsersApiController) RegisterUser(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)

	result := c.service.RegisterUser(userDataParam.Username, userDataParam.Password, &userDataParam.Newroles)

	if !handleError(result, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result.Body}, http.StatusCreated, w)
}

func extractUserDataFromRequest(r *http.Request) *UserData {
	userDataParam := UserData{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()

	err := d.Decode(&userDataParam)
	if err != nil {
		return nil
	}
	return &userDataParam
}

func handleError(result service.RequestResult, w http.ResponseWriter, uri string) bool {
	if result.ErrorStatus != nil {
		EncodeJSONResponse(result.ErrorStatus.Error(), result.ErrorStatus.ErrorCode, w)
		errorMessage := result.ErrorStatus.Message
		if result.ErrorStatus.WrappedError != nil {
			err := *result.ErrorStatus.WrappedError
			errorMessage = errorMessage + " : " + err.Error()
		}
		log.Printf("An error occured for %s: %s:", uri, errorMessage)
		return false
	}
	return true
}
