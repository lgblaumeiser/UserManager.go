// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package rest

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lgblaumeiser/usermanager/service"
)

type TokenResult struct {

	// A valid token
	AccessToken string `json:"access_token,omitempty"`

	// A valid token
	RefreshToken string `json:"refresh_token,omitempty"`
}

type userId struct {
	UserId string `json:"userid,omitempty"`
}

// UsersApiController binds http requests to an api service and writes the service results to the http response
type UsersApiController struct {
	service *service.UserService
}

// UsersApiOption for how the controller is set up.
type UsersApiOption func(*UsersApiController)

// NewUsersApiController creates a default api controller
func NewUsersApiController(s *service.UserService, opts ...UsersApiOption) Router {
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
			"InvalidateToken",
			strings.ToUpper("Put"),
			"/users/token",
			c.InvalidateToken,
		},
		{
			"RefreshToken",
			strings.ToUpper("Get"),
			"/users/token",
			c.RefreshToken,
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

	result, err := c.service.AuthenticateUser(userDataParam.Username, userDataParam.Password)

	if !handleError(err, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(TokenResult{result, ""}, http.StatusOK, w)
}

// ChangePassword - Change the password of the user, authentication provided either by token of user or of an admin
func (c *UsersApiController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	result, err := c.service.ChangePassword(userDataParam.Username, userDataParam.Password, requestor)

	if !handleError(err, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result}, http.StatusOK, w)
}

// ChangeRoles - Change roles of user, admin roles can only be changed by an admin
func (c *UsersApiController) ChangeRoles(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	result, err := c.service.ChangeRoles(userDataParam.Username, requestor, &userDataParam.Addroles, &userDataParam.Removeroles)

	if !handleError(err, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result}, http.StatusOK, w)
}

// DeleteUser - Delete a user and all its data from the database
func (c *UsersApiController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)
	requestor := r.Header.Get(UsernameHeader)

	err := c.service.DeleteUser(userDataParam.Username, requestor)

	if !handleError(err, w, r.RequestURI) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// InvalidateToken - Invalidate refresh token, in case token has been leaked and the usage has to be prevented, uses user, password authentication of the user or an admin token
func (c *UsersApiController) InvalidateToken(w http.ResponseWriter, r *http.Request) {
}

// RefreshToken - With the use of the old access token or the refresh token aquire a new access token, refresh token will be restarted as well
func (c *UsersApiController) RefreshToken(w http.ResponseWriter, r *http.Request) {
}

// RegisterUser - Register a new user, needs no authentication
func (c *UsersApiController) RegisterUser(w http.ResponseWriter, r *http.Request) {
	userDataParam := extractUserDataFromRequest(r)

	result, err := c.service.RegisterUser(userDataParam.Username, userDataParam.Password, &userDataParam.Addroles)

	if !handleError(err, w, r.RequestURI) {
		return
	}

	EncodeJSONResponse(userId{result}, http.StatusCreated, w)
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
