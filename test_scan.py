from janus.recon.sensitive_files import SensitiveFileScanner
scanner = SensitiveFileScanner(timeout=10)
report = scanner.scan('https://www.ctccalculator.in/')
print(f'Files found: {report.files_found}')
print(f'Verified: {report.verified_findings}')
for f in report.findings:
    evidence = f.evidence[:50] if f.evidence else "no evidence"
    print(f'  {f.file_type}: {f.confidence} - {evidence}')
