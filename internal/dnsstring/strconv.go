package dnsstring

import (
	"fmt"
	"strconv"
)

func ParseUint(s string) (int, error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if i < 0 {
		return 0, fmt.Errorf("negative value")
	}
	return i, nil
}
