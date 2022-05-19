// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package rest

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/util"
)

// InfrastructureApiController binds http requests to an api service and writes the service results to the http response
type InfrastructureApiController struct {
	service *service.UserService
}

// InfrastructureApiOption for how the controller is set up.
type InfrastructureApiOption func(*InfrastructureApiController)

// NewInfrastructureApiController creates a default api controller
func NewInfrastructureApiController(s *service.UserService, opts ...InfrastructureApiOption) Router {
	controller := &InfrastructureApiController{
		service: s,
	}

	for _, opt := range opts {
		opt(controller)
	}

	return controller
}

// Routes returns all of the api route for the InfrastructureApiController
func (c *InfrastructureApiController) Routes() Routes {
	return Routes{
		{
			"Backup",
			strings.ToUpper("Get"),
			"/backup",
			c.Backup,
		},
		{
			"License",
			strings.ToUpper("Get"),
			"/licenses",
			c.License,
		},
		{
			"Restore",
			strings.ToUpper("Put"),
			"/backup",
			c.Restore,
		},
	}
}

// Backup - Create a backup of the database
func (c *InfrastructureApiController) Backup(w http.ResponseWriter, r *http.Request) {
	requestor := r.Header.Get(UsernameHeader)

	result, err := c.service.Backup(requestor)
	if !handleError(err, w, r.RequestURI) {
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/zip")
	w.Write(*result)
}

// Restore - Restore a backup and replace existing database
func (c *InfrastructureApiController) Restore(w http.ResponseWriter, r *http.Request) {
	requestor := r.Header.Get(UsernameHeader)

	body, zerr := ioutil.ReadAll(r.Body)
	if zerr != nil {
		handleError(util.UnexpectedBehavior(&zerr), w, r.RequestURI)
		return
	}

	err := c.service.Restore(requestor, &body)
	if !handleError(err, w, r.RequestURI) {
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// License - Returns the attribution information on the used Open Source Software
func (c *InfrastructureApiController) License(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(licenses))
}

const licenses = `License information for user manager service

Licensed under MIT license:
Copyright (c) 2022 Lars Geyer-Blaumeiser

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Used third party software and licenses:
`
