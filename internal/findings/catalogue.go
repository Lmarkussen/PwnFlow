package findings

// Detection describes a deliberately narrow, evidence-backed detector. The
// catalogue is documentation as data: unsupported or derived relationships are
// not silently promoted to vulnerabilities.
type Detection struct {
	ID, Source, Condition, RequiredFields, Severity, Confidence, Remediation string
	Supported                                                                bool
}

func DetectionCatalogue() []Detection {
	return []Detection{
		{ID: "ad.acl.writedacl", Source: "RustHound-CE", Condition: "direct WriteDacl ACE", RequiredFields: "PrincipalSID, ObjectIdentifier, RightName", Severity: "medium/high when sensitive", Confidence: "observed-direct-ace", Remediation: "review principal and remove unnecessary control", Supported: true},
		{ID: "ad.acl.genericall", Source: "RustHound-CE", Condition: "direct GenericAll ACE", RequiredFields: "PrincipalSID, ObjectIdentifier, RightName", Severity: "medium/high when sensitive", Confidence: "observed-direct-ace", Remediation: "review broad object control", Supported: true},
		{ID: "ad.acl.shadow-credentials-potential", Source: "RustHound-CE", Condition: "direct AddKeyCredentialLink ACE", RequiredFields: "PrincipalSID, ObjectIdentifier, RightName", Severity: "medium/high when sensitive", Confidence: "potential-condition", Remediation: "verify account control and key-credential policy", Supported: true},
		{ID: "ad.acl.replication-partial", Source: "RustHound-CE", Condition: "one or more replication rights", RequiredFields: "PrincipalSID, domain ObjectIdentifier, RightName", Severity: "informational until complete", Confidence: "partial-observation", Remediation: "verify the complete replication-right set", Supported: true},
		{ID: "protocol.smb-signing", Source: "NetExec", Condition: "explicit signing-not-required evidence", RequiredFields: "host, signing policy", Severity: "medium", Confidence: "tool-confirmed", Remediation: "require SMB signing", Supported: true},
		{ID: "ad.account.passwd-not-required", Source: "NetExec", Condition: "explicit PASSWD_NOTREQD user-account-control flag", RequiredFields: "account, userAccountControl", Severity: "context-dependent", Confidence: "explicit-uac-flag", Remediation: "review and clear the flag where unnecessary", Supported: true},
		{ID: "ad.account.dont-expire-password", Source: "NetExec", Condition: "explicit DONT_EXPIRE_PASSWORD user-account-control flag", RequiredFields: "account, userAccountControl", Severity: "context-dependent", Confidence: "explicit-uac-flag", Remediation: "review account credential lifecycle and rotation", Supported: true},
		{ID: "ad.domain.weak-minimum-password-length", Source: "NetExec", Condition: "domain default minimum password length below the documented review threshold", RequiredFields: "domain, minPwdLength", Severity: "low/context-dependent", Confidence: "observed-domain-default-policy", Remediation: "review the domain default and any fine-grained policy overrides", Supported: true},
		{ID: "ad.domain.password-expiration-not-enforced", Source: "NetExec", Condition: "domain default maxPwdAge is non-expiring", RequiredFields: "domain, maxPwdAge", Severity: "informational", Confidence: "observed-domain-default-policy", Remediation: "review password policy in context; do not infer account compromise", Supported: true},
		{ID: "ad.domain.machine-account-creation-quota", Source: "NetExec", Condition: "domain ms-DS-MachineAccountQuota is positive", RequiredFields: "domain, ms-DS-MachineAccountQuota", Severity: "informational/context-dependent", Confidence: "observed-domain-default-policy", Remediation: "review directory permissions and whether the quota is required", Supported: true},
		{ID: "protocol.ldap-signing", Source: "NetExec/RelayKing", Condition: "explicit LDAP signing policy evidence", RequiredFields: "host, policy evidence", Severity: "medium", Confidence: "tool-confirmed", Remediation: "require LDAP signing and validate channel binding", Supported: false},
		{ID: "adcs.esc-report", Source: "Certipy", Condition: "explicit ESC identifier in vulnerability output", RequiredFields: "template or CA, ESC identifier, vulnerability text", Severity: "context-dependent", Confidence: "tool-reported-esc", Remediation: "review the reported ESC condition and required prerequisites", Supported: true},
		{ID: "relay.explicit-path", Source: "RelayKing", Condition: "explicit classified relay path", RequiredFields: "destination, protocol, impact", Severity: "tool-classified", Confidence: "tool-reported-path", Remediation: "review signing, channel binding and relay destination", Supported: true},
	}
}
