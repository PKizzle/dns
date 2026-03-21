package model

import (
	"fmt"
)

const (
	TypeA    = "A"
	TypeAAAA = "AAAA"
)

func IsValidType(s string) error {
	switch s {
	case TypeA, TypeAAAA:
		return nil
	}

	return fmt.Errorf("invalid record type")
}

type DomainResponse struct {
	Name  string `json:"name,omitempty"`
	Token string `json:"token,omitempty"`
}

type RecordRequest struct {
	Name   string   `json:"name,omitempty"`
	Type   string   `json:"type,omitempty"`
	Values []string `json:"values,omitempty"`
}

type RecordResponse struct {
	RecordRequest
	FQDN string `json:"fqdn,omitempty"`
}

type ErrorResponse struct {
	Status  int    `json:"status,omitempty"`
	Message string `json:"msg,omitempty"`
	Data    any    `json:"data,omitempty"`
}
