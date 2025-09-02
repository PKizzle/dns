package dns

import "codeberg.org/miekg/dns/internal/reverse"

// StringToType is the reverse of TypeToString, needed for string parsing.
var StringToType = reverse.Int16(TypeToString)

// StringToClass is the reverse of ClassToString, needed for string parsing.
var StringToClass = reverse.Int16(ClassToString)

// StringToOpcode is a map of opcodes to strings.
var StringToOpcode = reverse.Int8(OpcodeToString)

// StringToRcode is a map of rcodes to strings.
var StringToRcode = reverse.Int16(RcodeToString)

// StringToAlgorithm is the reverse of AlgorithmToString.
var StringToAlgorithm = reverse.Int8(AlgorithmToString)

// StringToHash is a map of names to hash IDs.
var StringToHash = reverse.Int8(HashToString)

// StringToCertType is the reverseof CertTypeToString.
var StringToCertType = reverse.Int16(CertTypeToString)
