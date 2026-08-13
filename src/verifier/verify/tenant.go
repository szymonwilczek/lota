// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - device tenant extraction
//
// Attestation CA assigns each device to a tenant at enrollment and records it
// in the AIK certificate subject (OrganizationalUnit).
//
// Tenant partitions all verifier-side trust state:
// baselines, revocations, hardware bans, logs and session tokens are scoped to
// the tenant carried by the certificate, so one verifier can serve multiple
// isolated organisations or titles.
//
// Certificate carrying no OU falls into the default tenant, which is how deployment
// that assigns no tenants works.

package verify

import (
	"crypto/x509"
	"fmt"
)

// DefaultTenant is the tenant of every certificate issued without explicit assignment;
// pre-multi-tenancy deployment is exactly one fleet under this name.
const DefaultTenant = "default"

// MaxTenantLen bounds the tenant name.
// It fits store columns and log lines and leaves no room for delimiter smuggling.
const MaxTenantLen = 64

// TenantFromCertificate returns the tenant the CA recorded in the AIK certificate subject.
// No OU means the default tenant.
// Name is validated fail-closed: certificate carrying malformed or ambiguous tenant must
// not attest into anyone's fleet.
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
// Shared by the certificate path and the API-key scope loader so both
// sides of the trust boundary agree on the alphabet.
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
