package uncloud

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/uncloud/model"
)

const defaultToken = "Have fun!"

func (u *Uncloud) root(w http.ResponseWriter, r *http.Request) {
	writeSuccess(w, http.StatusOK, "OK")
}

func (u *Uncloud) getDomain(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("domain")
	writeSuccess(w, http.StatusOK, model.DomainResponse{Name: owner})
}

func (u *Uncloud) createDomain(w http.ResponseWriter, r *http.Request) {
	domain, err := u.CreateDomain()
	if err != nil {
		log().Debug("Create failed", Err(err))
		handleError(w, http.StatusInternalServerError, err)
		return
	}

	dr := model.DomainResponse{Name: domain, Token: defaultToken}
	writeSuccess(w, http.StatusCreated, dr)
}

func (u *Uncloud) createRecord(w http.ResponseWriter, r *http.Request) {
	var input model.RecordRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		handleError(w, http.StatusBadRequest, err)
		return
	}

	if err := validateRecord(input); err != nil {
		handleError(w, http.StatusUnprocessableEntity, err)
		return
	}

	owner := r.PathValue("domain")
	domain := fromContext(r.Context())

	record, err := u.CreateRecord(owner, domain, input)
	if err != nil {
		handleError(w, http.StatusInternalServerError, err)
		return
	}

	writeSuccess(w, http.StatusCreated, record)
}

func validateRecord(input model.RecordRequest) error {
	if err := model.IsValidType(input.Type); err != nil {
		return err
	}

	if input.Name == "" {
		return fmt.Errorf("record name must be provided")
	}

	if len(input.Values) == 0 {
		return fmt.Errorf("must supply at least one value")
	}

	switch input.Type {
	case model.TypeA:
		for _, v := range input.Values {
			ip := net.ParseIP(v)
			if ip == nil || strings.Contains(v, ":") {
				return fmt.Errorf("value %v is not a valid IPv4 address", v)
			}
		}
	case model.TypeAAAA:
		for _, v := range input.Values {
			ip := net.ParseIP(v)
			if ip == nil || !strings.Contains(v, ":") {
				return fmt.Errorf("value %v is not a valid IPv6 address", v)
			}
		}
	}

	return nil
}
