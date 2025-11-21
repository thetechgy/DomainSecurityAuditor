@{
    Name = 'Baseline Email Security'
    Version = '1.0'
    Profiles = @{
        SendingOnly = @{
            Description = 'Domains that originate mail but do not host inbound mailboxes.'
            Checks = @(
                @{
                    Condition = 'GreaterThanOrEqual'
                    References = @(
                        'RFC 5321 §5',
                        'M3AAWG Operational Guidance'
                    )
                    ExpectedValue = 1
                    Expectation = 'Inbound-capable domains must publish MX records.'
                    Enforcement = 'Recommended'
                    Severity = 'Critical'
                    Area = 'MX'
                    Id = 'MXPresence'
                    Target = 'Records.MXRecordCount'
                    Remediation = 'Publish MX records pointing to the organization''s inbound infrastructure.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'M3AAWG Operational Guidance'
                    )
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'MX TTLs between 1 and 24 hours aid change control.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'MX'
                    Id = 'MXTtl'
                    Target = 'Records.MXMinimumTtl'
                    Remediation = 'Adjust MX TTL to fall within the recommended range.'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'Publish an SPF TXT record to define authorized senders.'
                    Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
                    Severity = 'Critical'
                    Area = 'SPF'
                    Id = 'SPFPresence'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFRecord'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = '1'
                    Expectation = 'Only one SPF record should exist per RFC 7208.'
                    Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFRecordMultiplicity'
                    References = @(
                        'RFC 7208 §3.1'
                    )
                    Target = 'Records.SPFRecordCount'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 10
                    Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
                    Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFLookupLimit'
                    References = @(
                        'RFC 7208 §4.6.4'
                    )
                    Target = 'Records.SPFLookupCount'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        '-all',
                        '~all'
                    )
                    Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
                    Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFTerminalMechanism'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTerminalMechanism'
                },
                @{
                    Condition = 'MustBeFalse'
                    Enforcement = 'Required'
                    Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
                    Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFUnsafeMechanisms'
                    References = @(
                        'RFC 7208 §5.7'
                    )
                    Target = 'Records.SPFHasPtrMechanism'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Recommended'
                    ExpectedValue = 255
                    Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
                    Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFRecordLength'
                    References = @(
                        'RFC 7208 §3.2'
                    )
                    Target = 'Records.SPFRecordLength'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'SPF TTL should balance agility with cache efficiency (1–24 hours).'
                    Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
                    Severity = 'Low'
                    Area = 'SPF'
                    Id = 'SPFTtl'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one DKIM selector should exist for active senders.'
                    Remediation = 'Generate 2048-bit DKIM keys per platform and publish selectors.'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorPresence'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMSelectors'
                },
                @{
                    Condition = 'GreaterThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 1024
                    Expectation = 'DKIM keys must be ≥1024 bits (2048 preferred).'
                    Remediation = 'Rotate weak DKIM keys with 2048-bit RSA entries.'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMKeyStrength'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMMinKeyLength'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 0
                    Expectation = 'Selectors should resolve cleanly without invalid/weak keys.'
                    Remediation = 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.'
                    Severity = 'Medium'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorHealth'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMWeakSelectors'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 604800
                    }
                    Expectation = 'DKIM records should retain TTLs between 1 hour and 7 days.'
                    Remediation = 'Adjust selector TTLs to balance agility and cache stability.'
                    Severity = 'Low'
                    Area = 'DKIM'
                    Id = 'DKIMTtl'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMMinimumTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
                    Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
                    Severity = 'Critical'
                    Area = 'DMARC'
                    Id = 'DMARCPresence'
                    References = @(
                        'RFC 7489',
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRecord'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        'quarantine',
                        'reject'
                    )
                    Expectation = 'Active domains should enforce p=quarantine or p=reject.'
                    Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyStrength'
                    References = @(
                        'RFC 7489',
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCPolicy'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'DMARC must include at least one RUA reporting address.'
                    Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
                    Severity = 'Medium'
                    Area = 'DMARC'
                    Id = 'DMARCRuaPresence'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRuaAddresses'
                },
                @{
                    Condition = 'MustBeEmpty'
                    Enforcement = 'Recommended'
                    Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
                    Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCRufOmission'
                    References = @(
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCRufAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
                    Remediation = 'Adjust DMARC TXT TTL accordingly.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCTtl'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish the _mta-sts TXT bootstrap record.'
                    Remediation = 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPresence'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSRecordPresent'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'The HTTPS policy file should be reachable and parseable.'
                    Remediation = 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPolicyValid'
                    References = @(
                        'RFC 8461'
                    )
                    Target = 'Records.MTASTSPolicyValid'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 'enforce'
                    Expectation = 'Operate MTA-STS in enforce mode (not testing) once vetted.'
                    Remediation = 'Update the policy file mode to enforce after validating delivery.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSMode'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSMode'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'MTA-STS TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust the TXT TTL to balance agility and cache efficiency.'
                    Severity = 'Low'
                    Area = 'MTA-STS'
                    Id = 'MTASTSTtl'
                    References = @(
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
                    Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTPresence'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTRecordPresent'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one reporting mailbox should be defined.'
                    Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTAddresses'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'TLS-RPT TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
                    Severity = 'Low'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTTtl'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTTtl'
                }
            )
            Name = 'Sending Only'
        }
        Parked = @{
            Description = 'Domains not actively sending or receiving mail.'
            Checks = @(
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Parked domains should publish a null MX (0 .).'
                    Remediation = 'Add a null MX to signal that the domain does not accept mail.'
                    Severity = 'High'
                    Area = 'MX'
                    Id = 'MXNullForParked'
                    References = @(
                        'RFC 7504'
                    )
                    Target = 'Records.MXHasNull'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'Publish an SPF TXT record to define authorized senders.'
                    Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
                    Severity = 'Critical'
                    Area = 'SPF'
                    Id = 'SPFPresence'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFRecord'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = '1'
                    Expectation = 'Only one SPF record should exist per RFC 7208.'
                    Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFRecordMultiplicity'
                    References = @(
                        'RFC 7208 §3.1'
                    )
                    Target = 'Records.SPFRecordCount'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 10
                    Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
                    Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFLookupLimit'
                    References = @(
                        'RFC 7208 §4.6.4'
                    )
                    Target = 'Records.SPFLookupCount'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        '-all',
                        '~all'
                    )
                    Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
                    Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFTerminalMechanism'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTerminalMechanism'
                },
                @{
                    Condition = 'MustBeFalse'
                    Enforcement = 'Required'
                    Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
                    Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFUnsafeMechanisms'
                    References = @(
                        'RFC 7208 §5.7'
                    )
                    Target = 'Records.SPFHasPtrMechanism'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Recommended'
                    ExpectedValue = 255
                    Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
                    Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFRecordLength'
                    References = @(
                        'RFC 7208 §3.2'
                    )
                    Target = 'Records.SPFRecordLength'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'SPF TTL should balance agility with cache efficiency (1–24 hours).'
                    Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
                    Severity = 'Low'
                    Area = 'SPF'
                    Id = 'SPFTtl'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTtl'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        '-all'
                    )
                    Expectation = 'Parked domains should hard-fail with -all.'
                    Remediation = 'Set the SPF record to v=spf1 -all for unused domains.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFTerminalParked'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTerminalMechanism'
                },
                @{
                    Condition = 'MustBeEmpty'
                    Enforcement = 'Required'
                    Expectation = 'Parked domains should not include sending providers.'
                    Remediation = 'Remove SendGrid/Microsoft/etc. includes from parked SPF records.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFIncludesParked'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFIncludes'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Recommended'
                    Expectation = 'Configure an empty wildcard SPF record (e.g., *.domain) to return v=spf1 -all.'
                    Remediation = 'Publish a wildcard TXT record with v=spf1 -all for parked domains.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFWildcardParked'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFWildcardConfigured'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Expectation = 'At least one DKIM selector should exist for active senders.'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorPresence'
                    Target = 'Records.DKIMSelectors'
                    Remediation = 'Generate 2048-bit DKIM keys per platform and publish selectors.'
                },
                @{
                    Condition = 'GreaterThanOrEqual'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = 1024
                    Expectation = 'DKIM keys must be ≥1024 bits (2048 preferred).'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMKeyStrength'
                    Target = 'Records.DKIMMinKeyLength'
                    Remediation = 'Rotate weak DKIM keys with 2048-bit RSA entries.'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = 0
                    Expectation = 'Selectors should resolve cleanly without invalid/weak keys.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorHealth'
                    Target = 'Records.DKIMWeakSelectors'
                    Remediation = 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = @{
                        Min = 3600
                        Max = 604800
                    }
                    Expectation = 'DKIM records should retain TTLs between 1 hour and 7 days.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'DKIM'
                    Id = 'DKIMTtl'
                    Target = 'Records.DKIMMinimumTtl'
                    Remediation = 'Adjust selector TTLs to balance agility and cache stability.'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
                    Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
                    Severity = 'Critical'
                    Area = 'DMARC'
                    Id = 'DMARCPresence'
                    References = @(
                        'RFC 7489',
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRecord'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        'quarantine',
                        'reject'
                    )
                    Expectation = 'Active domains should enforce p=quarantine or p=reject.'
                    Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyStrength'
                    References = @(
                        'RFC 7489',
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCPolicy'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'DMARC must include at least one RUA reporting address.'
                    Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
                    Severity = 'Medium'
                    Area = 'DMARC'
                    Id = 'DMARCRuaPresence'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRuaAddresses'
                },
                @{
                    Condition = 'MustBeEmpty'
                    Enforcement = 'Recommended'
                    Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
                    Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCRufOmission'
                    References = @(
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCRufAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
                    Remediation = 'Adjust DMARC TXT TTL accordingly.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCTtl'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCTtl'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        'reject'
                    )
                    Expectation = 'Parked domains should publish DMARC p=reject.'
                    Remediation = 'Set DMARC policy to reject to block spoofing of unused space.'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyParked'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCPolicy'
                },
                @{
                    Condition = 'MustBeTrue'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Expectation = 'Publish the _mta-sts TXT bootstrap record.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPresence'
                    Target = 'Records.MTASTSRecordPresent'
                    Remediation = 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.'
                },
                @{
                    Condition = 'MustBeTrue'
                    References = @(
                        'RFC 8461'
                    )
                    Expectation = 'The HTTPS policy file should be reachable and parseable.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPolicyValid'
                    Target = 'Records.MTASTSPolicyValid'
                    Remediation = 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.'
                },
                @{
                    Condition = 'MustEqual'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    ExpectedValue = 'enforce'
                    Expectation = 'Operate MTA-STS in enforce mode (not testing) once vetted.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSMode'
                    Target = 'Records.MTASTSMode'
                    Remediation = 'Update the policy file mode to enforce after validating delivery.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'M3AAWG TLS Guidance'
                    )
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'MTA-STS TXT TTL should be 1–7 days.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'MTA-STS'
                    Id = 'MTASTSTtl'
                    Target = 'Records.MTASTSTtl'
                    Remediation = 'Adjust the TXT TTL to balance agility and cache efficiency.'
                },
                @{
                    Condition = 'MustBeTrue'
                    References = @(
                        'RFC 8460'
                    )
                    Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTPresence'
                    Target = 'Records.TLSRPTRecordPresent'
                    Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'RFC 8460'
                    )
                    Expectation = 'At least one reporting mailbox should be defined.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTAddresses'
                    Target = 'Records.TLSRPTAddresses'
                    Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'RFC 8460'
                    )
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'TLS-RPT TXT TTL should be 1–7 days.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTTtl'
                    Target = 'Records.TLSRPTTtl'
                    Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
                }
            )
            Name = 'Parked'
        }
        ReceivingOnly = @{
            Description = 'Domains that accept inbound mail but are not expected to send.'
            Checks = @(
                @{
                    Condition = 'GreaterThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 1
                    Expectation = 'Inbound-capable domains must publish MX records.'
                    Remediation = 'Publish MX records pointing to the organization''s inbound infrastructure.'
                    Severity = 'Critical'
                    Area = 'MX'
                    Id = 'MXPresence'
                    References = @(
                        'RFC 5321 §5',
                        'M3AAWG Operational Guidance'
                    )
                    Target = 'Records.MXRecordCount'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'MX TTLs between 1 and 24 hours aid change control.'
                    Remediation = 'Adjust MX TTL to fall within the recommended range.'
                    Severity = 'Low'
                    Area = 'MX'
                    Id = 'MXTtl'
                    References = @(
                        'M3AAWG Operational Guidance'
                    )
                    Target = 'Records.MXMinimumTtl'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Expectation = 'Publish an SPF TXT record to define authorized senders.'
                    Enforcement = 'Recommended'
                    Severity = 'Critical'
                    Area = 'SPF'
                    Id = 'SPFPresence'
                    Target = 'Records.SPFRecord'
                    Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
                },
                @{
                    Condition = 'MustEqual'
                    References = @(
                        'RFC 7208 §3.1'
                    )
                    ExpectedValue = '1'
                    Expectation = 'Only one SPF record should exist per RFC 7208.'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFRecordMultiplicity'
                    Target = 'Records.SPFRecordCount'
                    Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    References = @(
                        'RFC 7208 §4.6.4'
                    )
                    ExpectedValue = 10
                    Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFLookupLimit'
                    Target = 'Records.SPFLookupCount'
                    Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.'
                },
                @{
                    Condition = 'MustBeOneOf'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    ExpectedValue = @(
                        '-all',
                        '~all'
                    )
                    Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFTerminalMechanism'
                    Target = 'Records.SPFTerminalMechanism'
                    Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
                },
                @{
                    Condition = 'MustBeFalse'
                    References = @(
                        'RFC 7208 §5.7'
                    )
                    Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFUnsafeMechanisms'
                    Target = 'Records.SPFHasPtrMechanism'
                    Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    References = @(
                        'RFC 7208 §3.2'
                    )
                    ExpectedValue = 255
                    Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFRecordLength'
                    Target = 'Records.SPFRecordLength'
                    Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'SPF TTL should balance agility with cache efficiency (1–24 hours).'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'SPF'
                    Id = 'SPFTtl'
                    Target = 'Records.SPFTtl'
                    Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Expectation = 'At least one DKIM selector should exist for active senders.'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorPresence'
                    Target = 'Records.DKIMSelectors'
                    Remediation = 'Generate 2048-bit DKIM keys per platform and publish selectors.'
                },
                @{
                    Condition = 'GreaterThanOrEqual'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = 1024
                    Expectation = 'DKIM keys must be ≥1024 bits (2048 preferred).'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMKeyStrength'
                    Target = 'Records.DKIMMinKeyLength'
                    Remediation = 'Rotate weak DKIM keys with 2048-bit RSA entries.'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = 0
                    Expectation = 'Selectors should resolve cleanly without invalid/weak keys.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorHealth'
                    Target = 'Records.DKIMWeakSelectors'
                    Remediation = 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    ExpectedValue = @{
                        Min = 3600
                        Max = 604800
                    }
                    Expectation = 'DKIM records should retain TTLs between 1 hour and 7 days.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'DKIM'
                    Id = 'DKIMTtl'
                    Target = 'Records.DKIMMinimumTtl'
                    Remediation = 'Adjust selector TTLs to balance agility and cache stability.'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'RFC 7489',
                        'dmarc.org Deployment Guide'
                    )
                    Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
                    Enforcement = 'Recommended'
                    Severity = 'Critical'
                    Area = 'DMARC'
                    Id = 'DMARCPresence'
                    Target = 'Records.DMARCRecord'
                    Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
                },
                @{
                    Condition = 'MustBeOneOf'
                    References = @(
                        'RFC 7489',
                        'M3AAWG DMARC Deployment'
                    )
                    ExpectedValue = @(
                        'quarantine',
                        'reject'
                    )
                    Expectation = 'Active domains should enforce p=quarantine or p=reject.'
                    Enforcement = 'Recommended'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyStrength'
                    Target = 'Records.DMARCPolicy'
                    Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
                },
                @{
                    Condition = 'MustExist'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Expectation = 'DMARC must include at least one RUA reporting address.'
                    Enforcement = 'Recommended'
                    Severity = 'Medium'
                    Area = 'DMARC'
                    Id = 'DMARCRuaPresence'
                    Target = 'Records.DMARCRuaAddresses'
                    Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
                },
                @{
                    Condition = 'MustBeEmpty'
                    References = @(
                        'M3AAWG DMARC Deployment'
                    )
                    Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCRufOmission'
                    Target = 'Records.DMARCRufAddresses'
                    Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
                },
                @{
                    Condition = 'BetweenInclusive'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
                    Enforcement = 'Recommended'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCTtl'
                    Target = 'Records.DMARCTtl'
                    Remediation = 'Adjust DMARC TXT TTL accordingly.'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish the _mta-sts TXT bootstrap record.'
                    Remediation = 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPresence'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSRecordPresent'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'The HTTPS policy file should be reachable and parseable.'
                    Remediation = 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPolicyValid'
                    References = @(
                        'RFC 8461'
                    )
                    Target = 'Records.MTASTSPolicyValid'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 'enforce'
                    Expectation = 'Operate MTA-STS in enforce mode (not testing) once vetted.'
                    Remediation = 'Update the policy file mode to enforce after validating delivery.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSMode'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSMode'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'MTA-STS TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust the TXT TTL to balance agility and cache efficiency.'
                    Severity = 'Low'
                    Area = 'MTA-STS'
                    Id = 'MTASTSTtl'
                    References = @(
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
                    Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTPresence'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTRecordPresent'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one reporting mailbox should be defined.'
                    Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTAddresses'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'TLS-RPT TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
                    Severity = 'Low'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTTtl'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTTtl'
                }
            )
            Name = 'Receiving Only'
        }
        Default = @{
            Description = 'Fallback profile when classification cannot be determined.'
            Checks = @(
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'Publish an SPF TXT record to define authorized senders.'
                    Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
                    Severity = 'Critical'
                    Area = 'SPF'
                    Id = 'SPFPresence'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFRecord'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = '1'
                    Expectation = 'Only one SPF record should exist per RFC 7208.'
                    Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFRecordMultiplicity'
                    References = @(
                        'RFC 7208 §3.1'
                    )
                    Target = 'Records.SPFRecordCount'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 10
                    Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
                    Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFLookupLimit'
                    References = @(
                        'RFC 7208 §4.6.4'
                    )
                    Target = 'Records.SPFLookupCount'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        '-all',
                        '~all'
                    )
                    Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
                    Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFTerminalMechanism'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTerminalMechanism'
                },
                @{
                    Condition = 'MustBeFalse'
                    Enforcement = 'Required'
                    Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
                    Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFUnsafeMechanisms'
                    References = @(
                        'RFC 7208 §5.7'
                    )
                    Target = 'Records.SPFHasPtrMechanism'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Recommended'
                    ExpectedValue = 255
                    Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
                    Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFRecordLength'
                    References = @(
                        'RFC 7208 §3.2'
                    )
                    Target = 'Records.SPFRecordLength'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'SPF TTL should balance agility with cache efficiency (1–24 hours).'
                    Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
                    Severity = 'Low'
                    Area = 'SPF'
                    Id = 'SPFTtl'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
                    Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
                    Severity = 'Critical'
                    Area = 'DMARC'
                    Id = 'DMARCPresence'
                    References = @(
                        'RFC 7489',
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRecord'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        'quarantine',
                        'reject'
                    )
                    Expectation = 'Active domains should enforce p=quarantine or p=reject.'
                    Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyStrength'
                    References = @(
                        'RFC 7489',
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCPolicy'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'DMARC must include at least one RUA reporting address.'
                    Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
                    Severity = 'Medium'
                    Area = 'DMARC'
                    Id = 'DMARCRuaPresence'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRuaAddresses'
                },
                @{
                    Condition = 'MustBeEmpty'
                    Enforcement = 'Recommended'
                    Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
                    Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCRufOmission'
                    References = @(
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCRufAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
                    Remediation = 'Adjust DMARC TXT TTL accordingly.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCTtl'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
                    Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTPresence'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTRecordPresent'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one reporting mailbox should be defined.'
                    Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTAddresses'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'TLS-RPT TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
                    Severity = 'Low'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTTtl'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTTtl'
                }
            )
            Name = 'Default'
        }
        SendingAndReceiving = @{
            Description = 'Domains that both send and receive messages.'
            Checks = @(
                @{
                    Condition = 'GreaterThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 1
                    Expectation = 'Inbound-capable domains must publish MX records.'
                    Remediation = 'Publish MX records pointing to the organization''s inbound infrastructure.'
                    Severity = 'Critical'
                    Area = 'MX'
                    Id = 'MXPresence'
                    References = @(
                        'RFC 5321 §5',
                        'M3AAWG Operational Guidance'
                    )
                    Target = 'Records.MXRecordCount'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'MX TTLs between 1 and 24 hours aid change control.'
                    Remediation = 'Adjust MX TTL to fall within the recommended range.'
                    Severity = 'Low'
                    Area = 'MX'
                    Id = 'MXTtl'
                    References = @(
                        'M3AAWG Operational Guidance'
                    )
                    Target = 'Records.MXMinimumTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'Publish an SPF TXT record to define authorized senders.'
                    Remediation = 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.'
                    Severity = 'Critical'
                    Area = 'SPF'
                    Id = 'SPFPresence'
                    References = @(
                        'RFC 7208',
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFRecord'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = '1'
                    Expectation = 'Only one SPF record should exist per RFC 7208.'
                    Remediation = 'Consolidate multiple SPF TXT records into a single entry.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFRecordMultiplicity'
                    References = @(
                        'RFC 7208 §3.1'
                    )
                    Target = 'Records.SPFRecordCount'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 10
                    Expectation = 'SPF processing must stay within the 10 DNS lookup ceiling.'
                    Remediation = 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.'
                    Severity = 'High'
                    Area = 'SPF'
                    Id = 'SPFLookupLimit'
                    References = @(
                        'RFC 7208 §4.6.4'
                    )
                    Target = 'Records.SPFLookupCount'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        '-all',
                        '~all'
                    )
                    Expectation = 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.'
                    Remediation = 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFTerminalMechanism'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTerminalMechanism'
                },
                @{
                    Condition = 'MustBeFalse'
                    Enforcement = 'Required'
                    Expectation = 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.'
                    Remediation = 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFUnsafeMechanisms'
                    References = @(
                        'RFC 7208 §5.7'
                    )
                    Target = 'Records.SPFHasPtrMechanism'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Recommended'
                    ExpectedValue = 255
                    Expectation = 'Keep SPF strings within 255 characters to avoid DNS truncation.'
                    Remediation = 'Shorten mechanisms/includes or break records into multiple quoted strings.'
                    Severity = 'Medium'
                    Area = 'SPF'
                    Id = 'SPFRecordLength'
                    References = @(
                        'RFC 7208 §3.2'
                    )
                    Target = 'Records.SPFRecordLength'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'SPF TTL should balance agility with cache efficiency (1–24 hours).'
                    Remediation = 'Adjust TXT record TTL to between 3600 and 86400 seconds.'
                    Severity = 'Low'
                    Area = 'SPF'
                    Id = 'SPFTtl'
                    References = @(
                        'M3AAWG Email Authentication Best Practices'
                    )
                    Target = 'Records.SPFTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one DKIM selector should exist for active senders.'
                    Remediation = 'Generate 2048-bit DKIM keys per platform and publish selectors.'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorPresence'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMSelectors'
                },
                @{
                    Condition = 'GreaterThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 1024
                    Expectation = 'DKIM keys must be ≥1024 bits (2048 preferred).'
                    Remediation = 'Rotate weak DKIM keys with 2048-bit RSA entries.'
                    Severity = 'High'
                    Area = 'DKIM'
                    Id = 'DKIMKeyStrength'
                    References = @(
                        'RFC 6376',
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMMinKeyLength'
                },
                @{
                    Condition = 'LessThanOrEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 0
                    Expectation = 'Selectors should resolve cleanly without invalid/weak keys.'
                    Remediation = 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.'
                    Severity = 'Medium'
                    Area = 'DKIM'
                    Id = 'DKIMSelectorHealth'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMWeakSelectors'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 604800
                    }
                    Expectation = 'DKIM records should retain TTLs between 1 hour and 7 days.'
                    Remediation = 'Adjust selector TTLs to balance agility and cache stability.'
                    Severity = 'Low'
                    Area = 'DKIM'
                    Id = 'DKIMTtl'
                    References = @(
                        'M3AAWG DKIM Deployment Guide'
                    )
                    Target = 'Records.DKIMMinimumTtl'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'A DMARC TXT record must be present at _dmarc.<domain>.'
                    Remediation = 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).'
                    Severity = 'Critical'
                    Area = 'DMARC'
                    Id = 'DMARCPresence'
                    References = @(
                        'RFC 7489',
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRecord'
                },
                @{
                    Condition = 'MustBeOneOf'
                    Enforcement = 'Required'
                    ExpectedValue = @(
                        'quarantine',
                        'reject'
                    )
                    Expectation = 'Active domains should enforce p=quarantine or p=reject.'
                    Remediation = 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.'
                    Severity = 'High'
                    Area = 'DMARC'
                    Id = 'DMARCPolicyStrength'
                    References = @(
                        'RFC 7489',
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCPolicy'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'DMARC must include at least one RUA reporting address.'
                    Remediation = 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.'
                    Severity = 'Medium'
                    Area = 'DMARC'
                    Id = 'DMARCRuaPresence'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCRuaAddresses'
                },
                @{
                    Condition = 'MustBeEmpty'
                    Enforcement = 'Recommended'
                    Expectation = 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.'
                    Remediation = 'Remove ruf= values unless the workflow explicitly requires forensic data.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCRufOmission'
                    References = @(
                        'M3AAWG DMARC Deployment'
                    )
                    Target = 'Records.DMARCRufAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 3600
                        Max = 86400
                    }
                    Expectation = 'DMARC TTLs between 1 and 24 hours ease change control.'
                    Remediation = 'Adjust DMARC TXT TTL accordingly.'
                    Severity = 'Low'
                    Area = 'DMARC'
                    Id = 'DMARCTtl'
                    References = @(
                        'dmarc.org Deployment Guide'
                    )
                    Target = 'Records.DMARCTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish the _mta-sts TXT bootstrap record.'
                    Remediation = 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPresence'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSRecordPresent'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'The HTTPS policy file should be reachable and parseable.'
                    Remediation = 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSPolicyValid'
                    References = @(
                        'RFC 8461'
                    )
                    Target = 'Records.MTASTSPolicyValid'
                },
                @{
                    Condition = 'MustEqual'
                    Enforcement = 'Required'
                    ExpectedValue = 'enforce'
                    Expectation = 'Operate MTA-STS in enforce mode (not testing) once vetted.'
                    Remediation = 'Update the policy file mode to enforce after validating delivery.'
                    Severity = 'Medium'
                    Area = 'MTA-STS'
                    Id = 'MTASTSMode'
                    References = @(
                        'RFC 8461',
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSMode'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'MTA-STS TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust the TXT TTL to balance agility and cache efficiency.'
                    Severity = 'Low'
                    Area = 'MTA-STS'
                    Id = 'MTASTSTtl'
                    References = @(
                        'M3AAWG TLS Guidance'
                    )
                    Target = 'Records.MTASTSTtl'
                },
                @{
                    Condition = 'MustBeTrue'
                    Enforcement = 'Required'
                    Expectation = 'Publish _smtp._tls TXT for TLS Reporting.'
                    Remediation = 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTPresence'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTRecordPresent'
                },
                @{
                    Condition = 'MustExist'
                    Enforcement = 'Required'
                    Expectation = 'At least one reporting mailbox should be defined.'
                    Remediation = 'Add rua mailbox destinations to the TLS-RPT record.'
                    Severity = 'Medium'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTAddresses'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTAddresses'
                },
                @{
                    Condition = 'BetweenInclusive'
                    Enforcement = 'Recommended'
                    ExpectedValue = @{
                        Min = 86400
                        Max = 604800
                    }
                    Expectation = 'TLS-RPT TXT TTL should be 1–7 days.'
                    Remediation = 'Adjust TTL for TLS-RPT to improve manageability.'
                    Severity = 'Low'
                    Area = 'TLS-RPT'
                    Id = 'TLSRPTTtl'
                    References = @(
                        'RFC 8460'
                    )
                    Target = 'Records.TLSRPTTtl'
                }
            )
            Name = 'Sending and Receiving'
        }
    }
}
