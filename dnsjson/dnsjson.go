package dnsjson

// RR represents a DNS RR as specified in RFC 8427.
type RR struct {
	Name      string  `json:"NAME"`
	TTL       uint32  `json:"TTL"`
	TypeName  string  `json:"TYPEname,omitempty"`
	Type      uint16  `json:"TYPE,omitempty"`
	ClassName string  `json:"CLASSname,omitempty"`
	Class     uint16  `json:"CLASS,omitempty"`
	RdataHex  string  `json:"RDATAHEX,omitempty"`
	RRset     []RRset `json:"rrSet,omitempty"`
}

// RRset represents a DNS RRset as specified in RFC 8427.
type RRset struct {
	RdataHex string `json:"RDATAHEX"`
}
