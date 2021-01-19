// Package api provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package api

import (
	"net/http"

	"github.com/go-chi/chi"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Information about the CA.
	// (GET /ca)
	GetCa(w http.ResponseWriter, r *http.Request)
	// Prints the TOML configuration file.
	// (GET /config)
	GetConfig(w http.ResponseWriter, r *http.Request)
	// Basic information page about the control service process.
	// (GET /info)
	GetInfo(w http.ResponseWriter, r *http.Request)
	// Get logging level
	// (GET /log/level)
	GetLogLevel(w http.ResponseWriter, r *http.Request)
	// Set logging level
	// (PUT /log/level)
	SetLogLevel(w http.ResponseWriter, r *http.Request)
	// Prints information about the AS Certificate used to sign the control-plane message.
	// (GET /signer)
	GetSigner(w http.ResponseWriter, r *http.Request)
	// Prints the contents of the AS topology file.
	// (GET /topology)
	GetTopology(w http.ResponseWriter, r *http.Request)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetCa operation middleware
func (siw *ServerInterfaceWrapper) GetCa(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetCa(w, r.WithContext(ctx))
}

// GetConfig operation middleware
func (siw *ServerInterfaceWrapper) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetConfig(w, r.WithContext(ctx))
}

// GetInfo operation middleware
func (siw *ServerInterfaceWrapper) GetInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetInfo(w, r.WithContext(ctx))
}

// GetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetLogLevel(w, r.WithContext(ctx))
}

// SetLogLevel operation middleware
func (siw *ServerInterfaceWrapper) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.SetLogLevel(w, r.WithContext(ctx))
}

// GetSigner operation middleware
func (siw *ServerInterfaceWrapper) GetSigner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetSigner(w, r.WithContext(ctx))
}

// GetTopology operation middleware
func (siw *ServerInterfaceWrapper) GetTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.GetTopology(w, r.WithContext(ctx))
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerFromMux(si, chi.NewRouter())
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerFromMuxWithBaseURL(si, r, "")
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/ca", wrapper.GetCa)
	})
	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/config", wrapper.GetConfig)
	})
	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/info", wrapper.GetInfo)
	})
	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/log/level", wrapper.GetLogLevel)
	})
	r.Group(func(r chi.Router) {
		r.Put(baseURL+"/log/level", wrapper.SetLogLevel)
	})
	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/signer", wrapper.GetSigner)
	})
	r.Group(func(r chi.Router) {
		r.Get(baseURL+"/topology", wrapper.GetTopology)
	})

	return r
}
