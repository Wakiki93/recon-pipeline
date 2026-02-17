---
phase: quick/1-fix-the-dns-go-and-markdown-go-data-mode
plan: 1
type: execute
wave: 1
depends_on: []
files_modified:
  - internal/discovery/dns.go
autonomous: true

must_haves:
  truths:
    - "Resolved subdomains appear in markdown report with IP addresses"
    - "Report correctly identifies resolved vs unresolved subdomains"
    - "DNS resolution data is consistently stored in DNSRecords field"
  artifacts:
    - path: "internal/discovery/dns.go"
      provides: "Populates DNSRecords with A/AAAA records when IPs are found"
      min_lines: 90
  key_links:
    - from: "internal/discovery/dns.go"
      to: "internal/report/markdown.go"
      via: "DNSRecords array population"
      pattern: "DNSRecord.*DNSRecordA.*DNSRecordAAAA"
---

<objective>
Fix data model mismatch between DNS resolution code and markdown report generator.

Purpose: Ensure resolved subdomains with IPs appear in markdown reports correctly.
Output: Updated dns.go that populates DNSRecords array with A/AAAA records, enabling markdown.go to display resolved subdomains.
</objective>

<execution_context>
@C:/Users/Hakim/.claude/get-shit-done/workflows/execute-plan.md
@C:/Users/Hakim/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@C:/Users/Hakim/Desktop/recon-pipeline/.planning/PROJECT.md
@C:/Users/Hakim/Desktop/recon-pipeline/.planning/ROADMAP.md
@C:/Users/Hakim/Desktop/recon-pipeline/.planning/STATE.md
@C:/Users/Hakim/Desktop/recon-pipeline/.planning/phases/02-subdomain-discovery/02-VERIFICATION.md
@C:/Users/Hakim/Desktop/recon-pipeline/internal/discovery/dns.go
@C:/Users/Hakim/Desktop/recon-pipeline/internal/report/markdown.go
@C:/Users/Hakim/Desktop/recon-pipeline/internal/models/host.go
@C:/Users/Hakim/Desktop/recon-pipeline/internal/models/types.go
</context>

<tasks>

<task type="auto">
  <name>Update dns.go to populate DNSRecords with A/AAAA records</name>
  <files>internal/discovery/dns.go</files>
  <action>
Modify the ResolveBatch function in internal/discovery/dns.go to populate the DNSRecords array with A/AAAA records when IPs are resolved, in addition to setting sub.Resolved and sub.IPs.

Current code (lines 30-33):
```go
if dnsResult.Resolved {
    // Subdomain resolves - mark as resolved and store IPs
    subdomains[i].Resolved = true
    subdomains[i].IPs = dnsResult.IPs
}
```

Change to:
```go
if dnsResult.Resolved {
    // Subdomain resolves - mark as resolved and store IPs
    subdomains[i].Resolved = true
    subdomains[i].IPs = dnsResult.IPs

    // Populate DNSRecords with A/AAAA records for report generation
    // (markdown.go checks DNSRecords to identify resolved subdomains)
    for _, ip := range dnsResult.IPs {
        recordType := models.DNSRecordA
        if strings.Contains(ip, ":") {
            // IPv6 addresses contain colons
            recordType = models.DNSRecordAAAA
        }
        subdomains[i].DNSRecords = append(subdomains[i].DNSRecords, models.DNSRecord{
            Type:  recordType,
            Value: ip,
        })
    }
}
```

Add import for "strings" package at top of file if not already present.

Why this approach:
- Maintains backward compatibility (sub.Resolved and sub.IPs still populated)
- Aligns with markdown.go expectations (hasIPRecords and formatIPs check DNSRecords)
- Uses existing DNSRecord type system (DNSRecordA, DNSRecordAAAA from models/types.go)
- Simple IPv6 detection via colon presence (standard approach)
  </action>
  <verify>
Run existing test if available, or manually test:
```bash
cd /c/Users/Hakim/Desktop/recon-pipeline
go build -o reconpipe.exe ./cmd/reconpipe
./reconpipe discover -d example.com
cat scans/*/reports/subdomains.md
```

Verify that:
1. "Resolved Subdomains" section now shows subdomains with IPs (not "None found")
2. IP addresses appear in the IPs column (not "-")
3. Dangling DNS sections still work correctly
  </verify>
  <done>
- dns.go populates DNSRecords array with A/AAAA records when IPs are resolved
- strings package imported for IPv6 detection
- Code maintains both sub.IPs and sub.DNSRecords for compatibility
- markdown.go can now correctly identify and display resolved subdomains
  </done>
</task>

</tasks>

<verification>
Overall verification:

1. **Code correctness:**
   - DNSRecords populated with correct record types (A for IPv4, AAAA for IPv6)
   - No compilation errors
   - strings package imported

2. **Functional correctness:**
   - Run `reconpipe discover -d example.com` (or any test domain)
   - Check generated markdown report shows resolved subdomains with IPs
   - Verify "Resolved Subdomains" section is no longer empty when subdomains resolve

3. **No regressions:**
   - Dangling DNS detection still works (CNAME records still populated)
   - Source attribution preserved
   - Statistics counts remain accurate
</verification>

<success_criteria>
- [ ] internal/discovery/dns.go updated to populate DNSRecords array
- [ ] Code compiles without errors
- [ ] Manual test confirms resolved subdomains appear in markdown report
- [ ] IP addresses display correctly in report (not "-")
- [ ] No regression in dangling DNS functionality
- [ ] Changes committed to git
</success_criteria>

<output>
After completion, create `.planning/quick/1-fix-the-dns-go-and-markdown-go-data-mode/1-SUMMARY.md`
</output>
