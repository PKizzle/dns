package uncloud

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/uncloud/model"
	"codeberg.org/miekg/dns/dnsutil"
)

func (u *Uncloud) Serve(ln net.Listener) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", u.root)
	mux.HandleFunc("POST /v1/domains", u.createDomain)
	mux.HandleFunc("GET /v1/domains/{domain}", withContext(u, u.getDomain))
	mux.HandleFunc("POST /v1/domains/{domain}/records", withContext(u, u.createRecord))
	mux.HandleFunc("DELETE /v1/domains/{domain}/records/{record}", withContext(u, u.root)) // not implemented
	mux.HandleFunc("POST /v1/domains/{domain}/purgerecords", withContext(u, u.root))       // not implemented

	server := &http.Server{Handler: mux, ReadTimeout: 5 * time.Second}
	go func() { server.Serve(ln) }()
	return nil
}

func withContext(u *Uncloud, next http.HandlerFunc) http.HandlerFunc {
	return u.ContextMiddleware()(next).ServeHTTP
}

func (u *Uncloud) ContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log().Debug("Request URL", "path", r.URL.Path)

			domain := r.PathValue("domain")
			if domain == "" {
				handleError(w, http.StatusUnauthorized, errors.New("Must specify domain"))
				return
			}

			if !u.Domain(domain) {
				writeError(w, http.StatusUnauthorized, "Authentication failed", map[string]bool{"noDomain": true})
				return
			}

			ctx := context.WithValue(r.Context(), Domain, dnsutil.Fqdn(domain))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func fromContext(ctx context.Context) string { return ctx.Value(Domain).(string) }

type contextKey string

const Domain contextKey = "domain"

func writeError(w http.ResponseWriter, status int, message string, data any) {
	o := model.ErrorResponse{Status: status, Message: message, Data: data}
	res, _ := json.Marshal(o)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(res)
}

func handleError(w http.ResponseWriter, httpStatus int, err error) {
	writeError(w, httpStatus, err.Error(), nil)
}

func writeSuccess(w http.ResponseWriter, status int, data any) {
	res, err := json.Marshal(data)
	if err != nil {
		handleError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}
