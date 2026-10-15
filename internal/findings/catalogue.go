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
		{ID: "protocol.smb-signing", Source: "NetExec", Condition: "explicit signing-not-required evidence", RequiredFields: "host, signing policy", Severity: "medium", Confidence: "tool-confirmed", Remediation: "require SMB signing", Supported: false},
		{ID: "protocol.ldap-signing", Source: "NetExec/RelayKing", Condition: "explicit LDAP signing policy evidence", RequiredFields: "host, policy evidence", Severity: "medium", Confidence: "tool-confirmed", Remediation: "require LDAP signing and validate channel binding", Supported: false},
		{ID: "adcs.esc-report", Source: "Certipy", Condition: "explicit ESC identifier in vulnerability output", RequiredFields: "template or CA, ESC identifier, vulnerability text", Severity: "context-dependent", Confidence: "tool-reported-esc", Remediation: "review the reported ESC condition and required prerequisites", Supported: true},
		{ID: "relay.explicit-path", Source: "RelayKing", Condition: "explicit classified relay path", RequiredFields: "destination, protocol, impact", Severity: "tool-classified", Confidence: "tool-reported-path", Remediation: "review signing, channel binding and relay destination", Supported: true},
	}
}
