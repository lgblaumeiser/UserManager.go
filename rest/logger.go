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
	"log"
	"net/http"
	"time"
)

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Printf(
			"%s %s %s %s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}
