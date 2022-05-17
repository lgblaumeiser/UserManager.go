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

type UserData struct {
	Username string `json:"username,omitempty"`

	Password string `json:"password,omitempty"`

	Newroles []string `json:"newroles,omitempty"`

	Obsroles []string `json:"obsroles,omitempty"`
}
