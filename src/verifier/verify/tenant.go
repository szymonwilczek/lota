// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - device tenant extraction
//
// The attestation CA records a device's tenant as the one OrganizationalUnit
// of its AIK certificate subject, and leaves the OU out for the default
// tenant.

package verify

import (
	"crypto/x509"
	"fmt"
)

// DefaultTenant is the tenant of a certificate without an OU.
const DefaultTenant = "default"

// MaxTenantLen bounds the tenant name.
const MaxTenantLen = 64

// TenantFromCertificate returns the tenant the CA recorded in the AIK
// certificate subject: DefaultTenant with no OU, an error with more than one
// OU or a name ValidTenantName refuses.
func TenantFromCertificate(cert *x509.Certificate) (string, error) {
	ous := cert.Subject.OrganizationalUnit
	switch len(ous) {
	case 0:
		return DefaultTenant, nil
	case 1:
		if !ValidTenantName(ous[0]) {
			return "", fmt.Errorf("invalid tenant name in AIK certificate OU: %q", ous[0])
		}
		return ous[0], nil
	default:
		return "", fmt.Errorf("ambiguous tenant: %d OU entries in AIK certificate", len(ous))
	}
}

// ValidTenantName reports whether a tenant name is well-formed:
// lower-case alphanumerics and inner dashes, 1..MaxTenantLen characters.
func ValidTenantName(name string) bool {
	if name == "" || len(name) > MaxTenantLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
