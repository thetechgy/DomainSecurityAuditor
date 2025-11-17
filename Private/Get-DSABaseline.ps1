function Get-DSABaseline {
    [CmdletBinding()]
    param ()

    $newCheck = {
        param (
            [string]$Id,
            [string]$Area,
            [string]$Target,
            [string]$Condition,
            [string]$Expectation,
            [string]$Remediation,
            [string]$Severity,
            [string]$Enforcement = 'Required',
            [string[]]$References = @(),
            [object]$ExpectedValue
        )

        $definition = @{
            Id           = $Id
            Area         = $Area
            Target       = $Target
            Condition    = $Condition
            Expectation  = $Expectation
            Remediation  = $Remediation
            Severity     = $Severity
            Enforcement  = $Enforcement
            References   = $References
        }

        if ($PSBoundParameters.ContainsKey('ExpectedValue')) {
            $definition.ExpectedValue = $ExpectedValue
        }

        return $definition
    }

    $range = {
        param (
            [int]$Min,
            [int]$Max
        )

        return [pscustomobject]@{
            Min = $Min
            Max = $Max
        }
    }

    $cloneChecks = {
        param (
            [Parameter(Mandatory = $true)]
            [System.Collections.IEnumerable]$Checks,

            [string]$EnforcementOverride
        )

        $cloned = [System.Collections.Generic.List[object]]::new()
        foreach ($check in $Checks) {
            if ($check -is [System.ICloneable]) {
                $copy = $check.Clone()
            } else {
                $copy = @{}
                foreach ($key in $check.Keys) {
                    $copy[$key] = $check[$key]
                }
            }

            if ($PSBoundParameters.ContainsKey('EnforcementOverride')) {
                $copy['Enforcement'] = $EnforcementOverride
            }

            $cloned.Add($copy)
        }

        return $cloned.ToArray()
    }

    $spfActiveChecks = @(
        & $newCheck -Id 'SPFPresence' -Area 'SPF' -Target 'Records.SPFRecord' -Condition 'MustExist' -Expectation 'Publish an SPF TXT record to define authorized senders.' -Remediation 'Create a single SPF record (v=spf1 ...) for the domain and manage changes centrally.' -Severity 'Critical' -References @('RFC 7208', 'M3AAWG Email Authentication Best Practices')
        & $newCheck -Id 'SPFRecordMultiplicity' -Area 'SPF' -Target 'Records.SPFRecordCount' -Condition 'MustEqual' -ExpectedValue '1' -Expectation 'Only one SPF record should exist per RFC 7208.' -Remediation 'Consolidate multiple SPF TXT records into a single entry.' -Severity 'High' -References @('RFC 7208 §3.1')
        & $newCheck -Id 'SPFLookupLimit' -Area 'SPF' -Target 'Records.SPFLookupCount' -Condition 'LessThanOrEqual' -ExpectedValue 10 -Expectation 'SPF processing must stay within the 10 DNS lookup ceiling.' -Remediation 'Reduce includes/redirects by flattening or delegating per RFC 7208 §4.6.4.' -Severity 'High' -References @('RFC 7208 §4.6.4')
        & $newCheck -Id 'SPFTerminalMechanism' -Area 'SPF' -Target 'Records.SPFTerminalMechanism' -Condition 'MustBeOneOf' -ExpectedValue @('-all', '~all') -Expectation 'SPF should conclude with -all or ~all to provide deterministic policy enforcement.' -Remediation 'Update the SPF record terminal mechanism to -all after validating authorized senders (or ~all during phased rollout).' -Severity 'Medium' -References @('M3AAWG Email Authentication Best Practices')
        & $newCheck -Id 'SPFUnsafeMechanisms' -Area 'SPF' -Target 'Records.SPFHasPtrMechanism' -Condition 'MustBeFalse' -Expectation 'Avoid unsafe mechanisms such as ptr per RFC 7208 guidance.' -Remediation 'Remove ptr or other deprecated mechanisms to prevent unpredictable resolution chains.' -Severity 'Medium' -References @('RFC 7208 §5.7')
        & $newCheck -Id 'SPFRecordLength' -Area 'SPF' -Target 'Records.SPFRecordLength' -Condition 'LessThanOrEqual' -ExpectedValue 255 -Expectation 'Keep SPF strings within 255 characters to avoid DNS truncation.' -Remediation 'Shorten mechanisms/includes or break records into multiple quoted strings.' -Severity 'Medium' -Enforcement 'Recommended' -References @('RFC 7208 §3.2')
        & $newCheck -Id 'SPFTtl' -Area 'SPF' -Target 'Records.SPFTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 3600 86400) -Expectation 'SPF TTL should balance agility with cache efficiency (1–24 hours).' -Remediation 'Adjust TXT record TTL to between 3600 and 86400 seconds.' -Severity 'Low' -Enforcement 'Recommended' -References @('M3AAWG Email Authentication Best Practices')
    )

    $spfParkedChecks = @(
        & $newCheck -Id 'SPFTerminalParked' -Area 'SPF' -Target 'Records.SPFTerminalMechanism' -Condition 'MustBeOneOf' -ExpectedValue @('-all') -Expectation 'Parked domains should hard-fail with -all.' -Remediation 'Set the SPF record to v=spf1 -all for unused domains.' -Severity 'High' -References @('RFC 7208', 'M3AAWG Email Authentication Best Practices')
        & $newCheck -Id 'SPFIncludesParked' -Area 'SPF' -Target 'Records.SPFIncludes' -Condition 'MustBeEmpty' -Expectation 'Parked domains should not include sending providers.' -Remediation 'Remove SendGrid/Microsoft/etc. includes from parked SPF records.' -Severity 'Medium' -References @('M3AAWG Email Authentication Best Practices')
        & $newCheck -Id 'SPFWildcardParked' -Area 'SPF' -Target 'Records.SPFWildcardConfigured' -Condition 'MustBeTrue' -Expectation 'Configure an empty wildcard SPF record (e.g., *.domain) to return v=spf1 -all.' -Remediation 'Publish a wildcard TXT record with v=spf1 -all for parked domains.' -Severity 'Medium' -Enforcement 'Recommended' -References @('M3AAWG Email Authentication Best Practices')
    )

    $dkimChecks = @(
        & $newCheck -Id 'DKIMSelectorPresence' -Area 'DKIM' -Target 'Records.DKIMSelectors' -Condition 'MustExist' -Expectation 'At least one DKIM selector should exist for active senders.' -Remediation 'Generate 2048-bit DKIM keys per platform and publish selectors.' -Severity 'High' -References @('RFC 6376', 'M3AAWG DKIM Deployment Guide')
        & $newCheck -Id 'DKIMKeyStrength' -Area 'DKIM' -Target 'Records.DKIMMinKeyLength' -Condition 'GreaterThanOrEqual' -ExpectedValue 1024 -Expectation 'DKIM keys must be ≥1024 bits (2048 preferred).' -Remediation 'Rotate weak DKIM keys with 2048-bit RSA entries.' -Severity 'High' -References @('RFC 6376', 'M3AAWG DKIM Deployment Guide')
        & $newCheck -Id 'DKIMSelectorHealth' -Area 'DKIM' -Target 'Records.DKIMWeakSelectors' -Condition 'LessThanOrEqual' -ExpectedValue 0 -Expectation 'Selectors should resolve cleanly without invalid/weak keys.' -Remediation 'Repair or remove DKIM selectors flagged as invalid or <1024 bits.' -Severity 'Medium' -References @('M3AAWG DKIM Deployment Guide')
        & $newCheck -Id 'DKIMTtl' -Area 'DKIM' -Target 'Records.DKIMMinimumTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 3600 604800) -Expectation 'DKIM records should retain TTLs between 1 hour and 7 days.' -Remediation 'Adjust selector TTLs to balance agility and cache stability.' -Severity 'Low' -Enforcement 'Recommended' -References @('M3AAWG DKIM Deployment Guide')
    )

    $dmarcActiveChecks = @(
        & $newCheck -Id 'DMARCPresence' -Area 'DMARC' -Target 'Records.DMARCRecord' -Condition 'MustExist' -Expectation 'A DMARC TXT record must be present at _dmarc.<domain>.' -Remediation 'Publish DMARC (v=DMARC1; p=quarantine/reject; rua=mailto:reports@domain).' -Severity 'Critical' -References @('RFC 7489', 'dmarc.org Deployment Guide')
        & $newCheck -Id 'DMARCPolicyStrength' -Area 'DMARC' -Target 'Records.DMARCPolicy' -Condition 'MustBeOneOf' -ExpectedValue @('quarantine', 'reject') -Expectation 'Active domains should enforce p=quarantine or p=reject.' -Remediation 'Tighten DMARC to quarantine/reject after monitoring aligned traffic.' -Severity 'High' -References @('RFC 7489', 'M3AAWG DMARC Deployment')
        & $newCheck -Id 'DMARCRuaPresence' -Area 'DMARC' -Target 'Records.DMARCRuaAddresses' -Condition 'MustExist' -Expectation 'DMARC must include at least one RUA reporting address.' -Remediation 'Add rua=mailto:dmarc@domain to capture aggregate telemetry.' -Severity 'Medium' -References @('dmarc.org Deployment Guide')
        & $newCheck -Id 'DMARCRufOmission' -Area 'DMARC' -Target 'Records.DMARCRufAddresses' -Condition 'MustBeEmpty' -Expectation 'Avoid RUF forensic feeds unless mandated; they add privacy/risk.' -Remediation 'Remove ruf= values unless the workflow explicitly requires forensic data.' -Severity 'Low' -Enforcement 'Recommended' -References @('M3AAWG DMARC Deployment')
        & $newCheck -Id 'DMARCTtl' -Area 'DMARC' -Target 'Records.DMARCTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 3600 86400) -Expectation 'DMARC TTLs between 1 and 24 hours ease change control.' -Remediation 'Adjust DMARC TXT TTL accordingly.' -Severity 'Low' -Enforcement 'Recommended' -References @('dmarc.org Deployment Guide')
    )

    $dmarcParkedChecks = @(
        & $newCheck -Id 'DMARCPolicyParked' -Area 'DMARC' -Target 'Records.DMARCPolicy' -Condition 'MustBeOneOf' -ExpectedValue @('reject') -Expectation 'Parked domains should publish DMARC p=reject.' -Remediation 'Set DMARC policy to reject to block spoofing of unused space.' -Severity 'High' -References @('dmarc.org Deployment Guide')
    )

    $mtaStsChecks = @(
        & $newCheck -Id 'MTASTSPresence' -Area 'MTA-STS' -Target 'Records.MTASTSRecordPresent' -Condition 'MustBeTrue' -Expectation 'Publish the _mta-sts TXT bootstrap record.' -Remediation 'Create the _mta-sts subdomain TXT pointing to the HTTPS policy file.' -Severity 'Medium' -References @('RFC 8461', 'M3AAWG TLS Guidance')
        & $newCheck -Id 'MTASTSPolicyValid' -Area 'MTA-STS' -Target 'Records.MTASTSPolicyValid' -Condition 'MustBeTrue' -Expectation 'The HTTPS policy file should be reachable and parseable.' -Remediation 'Verify policy hosting, TLS certificate, and JSON syntax for the MTA-STS policy file.' -Severity 'Medium' -References @('RFC 8461')
        & $newCheck -Id 'MTASTSMode' -Area 'MTA-STS' -Target 'Records.MTASTSMode' -Condition 'MustEqual' -ExpectedValue 'enforce' -Expectation 'Operate MTA-STS in enforce mode (not testing) once vetted.' -Remediation 'Update the policy file mode to enforce after validating delivery.' -Severity 'Medium' -References @('RFC 8461', 'M3AAWG TLS Guidance')
        & $newCheck -Id 'MTASTSTtl' -Area 'MTA-STS' -Target 'Records.MTASTSTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 86400 604800) -Expectation 'MTA-STS TXT TTL should be 1–7 days.' -Remediation 'Adjust the TXT TTL to balance agility and cache efficiency.' -Severity 'Low' -Enforcement 'Recommended' -References @('M3AAWG TLS Guidance')
    )

    $tlsRptChecks = @(
        & $newCheck -Id 'TLSRPTPresence' -Area 'TLS-RPT' -Target 'Records.TLSRPTRecordPresent' -Condition 'MustBeTrue' -Expectation 'Publish _smtp._tls TXT for TLS Reporting.' -Remediation 'Create v=TLSRPTv1; rua=mailto:tls@domain at _smtp._tls.' -Severity 'Medium' -References @('RFC 8460')
        & $newCheck -Id 'TLSRPTAddresses' -Area 'TLS-RPT' -Target 'Records.TLSRPTAddresses' -Condition 'MustExist' -Expectation 'At least one reporting mailbox should be defined.' -Remediation 'Add rua mailbox destinations to the TLS-RPT record.' -Severity 'Medium' -References @('RFC 8460')
        & $newCheck -Id 'TLSRPTTtl' -Area 'TLS-RPT' -Target 'Records.TLSRPTTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 86400 604800) -Expectation 'TLS-RPT TXT TTL should be 1–7 days.' -Remediation 'Adjust TTL for TLS-RPT to improve manageability.' -Severity 'Low' -Enforcement 'Recommended' -References @('RFC 8460')
    )

    $mxActiveChecks = @(
        & $newCheck -Id 'MXPresence' -Area 'MX' -Target 'Records.MXRecordCount' -Condition 'GreaterThanOrEqual' -ExpectedValue 1 -Expectation 'Inbound-capable domains must publish MX records.' -Remediation 'Publish MX records pointing to the organization''s inbound infrastructure.' -Severity 'Critical' -References @('RFC 5321 §5', 'M3AAWG Operational Guidance')
        & $newCheck -Id 'MXTtl' -Area 'MX' -Target 'Records.MXMinimumTtl' -Condition 'BetweenInclusive' -ExpectedValue (& $range 3600 86400) -Expectation 'MX TTLs between 1 and 24 hours aid change control.' -Remediation 'Adjust MX TTL to fall within the recommended range.' -Severity 'Low' -Enforcement 'Recommended' -References @('M3AAWG Operational Guidance')
    )

    $mxParkedChecks = @(
        & $newCheck -Id 'MXNullForParked' -Area 'MX' -Target 'Records.MXHasNull' -Condition 'MustBeTrue' -Expectation 'Parked domains should publish a null MX (0 .).' -Remediation 'Add a null MX to signal that the domain does not accept mail.' -Severity 'High' -References @('RFC 7504')
    )

    $baseline = @{
        SendingAndReceiving = @{
            Name        = 'Sending and Receiving'
            Description = 'Domains that both send and receive messages.'
            Checks      = $mxActiveChecks + $spfActiveChecks + $dkimChecks + $dmarcActiveChecks + $mtaStsChecks + $tlsRptChecks
        }
        SendingOnly = @{
            Name        = 'Sending Only'
            Description = 'Domains that originate mail but do not host inbound mailboxes.'
            Checks      = (& $cloneChecks -Checks $mxActiveChecks -EnforcementOverride 'Recommended') + $spfActiveChecks + $dkimChecks + $dmarcActiveChecks + $mtaStsChecks + $tlsRptChecks
        }
        ReceivingOnly = @{
            Name        = 'Receiving Only'
            Description = 'Domains that accept inbound mail but are not expected to send.'
            Checks      = $mxActiveChecks + (& $cloneChecks -Checks $spfActiveChecks -EnforcementOverride 'Recommended') + (& $cloneChecks -Checks $dkimChecks -EnforcementOverride 'Recommended') + (& $cloneChecks -Checks $dmarcActiveChecks -EnforcementOverride 'Recommended') + $mtaStsChecks + $tlsRptChecks
        }
        Parked = @{
            Name        = 'Parked'
            Description = 'Domains not actively sending or receiving mail.'
            Checks      = $mxParkedChecks + $spfActiveChecks + $spfParkedChecks + (& $cloneChecks -Checks $dkimChecks -EnforcementOverride 'Recommended') + $dmarcActiveChecks + $dmarcParkedChecks + (& $cloneChecks -Checks $mtaStsChecks -EnforcementOverride 'Recommended') + (& $cloneChecks -Checks $tlsRptChecks -EnforcementOverride 'Recommended')
        }
        Default = @{
            Name        = 'Unknown'
            Description = 'Fallback profile when classification cannot be determined.'
            Checks      = $spfActiveChecks + $dmarcActiveChecks + $tlsRptChecks
        }
    }

    return $baseline
}
