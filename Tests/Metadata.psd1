<#
.SYNOPSIS
    Test metadata for DomainSecurityAuditor compliance checks.
.DESCRIPTION
    Maps test IDs to their metadata (Area, Severity, Enforcement, Expectation, Remediation, References).
    Used by ConvertFrom-PesterResult to enrich Pester test results for report generation.
#>
@{
    #region MX Checks
    MXPresence = @{
        Area        = 'MX'
        Severity    = 'Critical'
        Enforcement = 'Required'
        Expectation = 'Inbound-capable domains must publish MX records.'
        Remediation = 'Publish MX records pointing to the organization''s inbound infrastructure.'
        References  = @('RFC 5321 section 5', 'M3AAWG Operational Guidance')
    }
    MXTtl = @{
        Area        = 'MX'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'MX TTLs between 1 and 24 hours aid change control.'
        Remediation = 'Adjust MX TTL to fall within the recommended range.'
        References  = @('M3AAWG Operational Guidance')
    }
    MXNullForParked = @{
        Area        = 'MX'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'Parked domains should publish a null MX (0 .).'
        Remediation = 'Add a null MX to signal that the domain does not accept mail.'
        References  = @('RFC 7504')
    }
    #endregion

    #region SPF Checks
    SPFPresence = @{
        Area        = 'SPF'
        Severity    = 'Critical'
        Enforcement = 'Required'
        Expectation = 'Publish an SPF TXT record to define authorized senders.'
        Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
        References  = @('RFC 7208', 'M3AAWG Email Authentication Best Practices')
    }
    SPFRecordMultiplicity = @{
        Area        = 'SPF'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'Only one SPF record should exist per RFC 7208.'
        Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
        References  = @('RFC 7208 section 3.1')
    }
    SPFLookupLimit = @{
        Area        = 'SPF'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
        Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 section 4.6.4.'
        References  = @('RFC 7208 section 4.6.4')
    }
    SPFTerminalMechanism = @{
        Area        = 'SPF'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
        Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
        References  = @('M3AAWG Email Authentication Best Practices')
    }
    SPFUnsafeMechanisms = @{
        Area        = 'SPF'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
        Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
        References  = @('RFC 7208 section 5.7')
    }
    SPFRecordLength = @{
        Area        = 'SPF'
        Severity    = 'Medium'
        Enforcement = 'Recommended'
        Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
        Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
        References  = @('RFC 7208 section 3.2')
    }
    SPFTtl = @{
        Area        = 'SPF'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'SPF TTL should balance agility with cache efficiency (1-24 hours).'
        Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
        References  = @('M3AAWG Email Authentication Best Practices')
    }
    SPFTerminalParked = @{
        Area        = 'SPF'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'Parked domains should hard-fail with -all.'
        Remediation = 'Set the SPF record to v=spf1 -all for unused domains.'
        References  = @('RFC 7208', 'M3AAWG Email Authentication Best Practices')
    }
    SPFIncludesParked = @{
        Area        = 'SPF'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Parked domains should not include sending providers.'
        Remediation = 'Remove SendGrid/Microsoft/etc. includes from parked SPF records.'
        References  = @('M3AAWG Email Authentication Best Practices')
    }
    SPFWildcardParked = @{
        Area        = 'SPF'
        Severity    = 'Medium'
        Enforcement = 'Recommended'
        Expectation = 'Configure an empty wildcard SPF record (e.g., *.domain) to return v=spf1 -all.'
        Remediation = 'Publish a wildcard TXT record with v=spf1 -all for parked domains.'
        References  = @('M3AAWG Email Authentication Best Practices')
    }
    #endregion

    #region DKIM Checks
    DKIMSelectorPresence = @{
        Area        = 'DKIM'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'At least one DKIM selector should exist for active senders.'
        Remediation = 'Generate 2048-bit DKIM keys per platform and publish selectors.'
        References  = @('RFC 6376', 'M3AAWG DKIM Deployment Guide')
    }
    DKIMKeyStrength = @{
        Area        = 'DKIM'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'DKIM keys must be >=1024 bits (2048 preferred).'
        Remediation = 'Rotate weak DKIM keys with 2048-bit RSA entries.'
        References  = @('RFC 6376', 'M3AAWG DKIM Deployment Guide')
    }
    DKIMSelectorHealth = @{
        Area        = 'DKIM'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Selectors should resolve cleanly without invalid/weak keys.'
        Remediation = 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.'
        References  = @('M3AAWG DKIM Deployment Guide')
    }
    DKIMTtl = @{
        Area        = 'DKIM'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'DKIM records should retain TTLs between 1 hour and 7 days.'
        Remediation = 'Adjust selector TTLs to balance agility and cache stability.'
        References  = @('M3AAWG DKIM Deployment Guide')
    }
    #endregion

    #region DMARC Checks
    DMARCPresence = @{
        Area        = 'DMARC'
        Severity    = 'Critical'
        Enforcement = 'Required'
        Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
        Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
        References  = @('RFC 7489', 'dmarc.org Deployment Guide')
    }
    DMARCPolicyStrength = @{
        Area        = 'DMARC'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'Active domains should enforce p=quarantine or p=reject.'
        Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
        References  = @('RFC 7489', 'M3AAWG DMARC Deployment')
    }
    DMARCRuaPresence = @{
        Area        = 'DMARC'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'DMARC must include at least one RUA reporting address.'
        Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
        References  = @('dmarc.org Deployment Guide')
    }
    DMARCRufOmission = @{
        Area        = 'DMARC'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
        Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
        References  = @('M3AAWG DMARC Deployment')
    }
    DMARCTtl = @{
        Area        = 'DMARC'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
        Remediation = 'Adjust DMARC TXT TTL accordingly.'
        References  = @('dmarc.org Deployment Guide')
    }
    DMARCPolicyParked = @{
        Area        = 'DMARC'
        Severity    = 'High'
        Enforcement = 'Required'
        Expectation = 'Parked domains should publish DMARC p=reject.'
        Remediation = 'Set DMARC policy to reject to block spoofing of unused space.'
        References  = @('dmarc.org Deployment Guide')
    }
    #endregion

    #region MTA-STS Checks
    MTASTSPresence = @{
        Area        = 'MTA-STS'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Publish the _mta-sts TXT bootstrap record.'
        Remediation = 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.'
        References  = @('RFC 8461', 'M3AAWG TLS Guidance')
    }
    MTASTSPolicyValid = @{
        Area        = 'MTA-STS'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'The HTTPS policy file should be reachable and parseable.'
        Remediation = 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.'
        References  = @('RFC 8461')
    }
    MTASTSMode = @{
        Area        = 'MTA-STS'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Operate MTA-STS in enforce mode (not testing) once vetted.'
        Remediation = 'Update the policy file mode to enforce after validating delivery.'
        References  = @('RFC 8461', 'M3AAWG TLS Guidance')
    }
    MTASTSTtl = @{
        Area        = 'MTA-STS'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'MTA-STS TXT TTL should be 1-7 days.'
        Remediation = 'Adjust the TXT TTL to balance agility and cache efficiency.'
        References  = @('M3AAWG TLS Guidance')
    }
    #endregion

    #region TLS-RPT Checks
    TLSRPTPresence = @{
        Area        = 'TLS-RPT'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
        Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
        References  = @('RFC 8460')
    }
    TLSRPTAddresses = @{
        Area        = 'TLS-RPT'
        Severity    = 'Medium'
        Enforcement = 'Required'
        Expectation = 'At least one reporting mailbox should be defined.'
        Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
        References  = @('RFC 8460')
    }
    TLSRPTTtl = @{
        Area        = 'TLS-RPT'
        Severity    = 'Low'
        Enforcement = 'Recommended'
        Expectation = 'TLS-RPT TXT TTL should be 1-7 days.'
        Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
        References  = @('RFC 8460')
    }
    #endregion
}
