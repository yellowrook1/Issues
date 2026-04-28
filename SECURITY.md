# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, **please do not open a public GitHub issue**.

Instead, follow the responsible disclosure process below:

1. **Email** the maintainers directly at the address listed in the repository's `CODEOWNERS` or profile.
2. Include in your report:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if any)
3. You will receive an acknowledgement within **48 hours** and a full response within **7 days**.
4. We will coordinate a fix and a public disclosure timeline with you.

We follow the [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html) model.

## Security Controls

This repository uses the following automated security controls:

| Control | Tool | Schedule |
|---------|------|----------|
| Static Application Security Testing (SAST) | GitHub CodeQL | Every push to `main`; weekly |
| Secret / credential scanning | TruffleHog + Gitleaks | Every push; daily |
| Dependency vulnerability scanning | Dependency Review Action + Trivy | Every PR |
| Supply-chain security score | OSSF Scorecard | Weekly |
| Software Bill of Materials (SBOM) | `actions/dependency-submission` | Every push to `main` |
| License compliance | `pip-licenses` / `license-checker` | Every PR |
| Workflow security audit | Custom shell scripts | Every push to `.github/workflows/**` |
| Branch protection audit | GitHub REST API | Daily |
| Pinned-action audit | Custom shell script | Every push to `.github/workflows/**` |

## Threat Model

### In-scope threats

- **Dependency confusion / supply-chain attacks** – mitigated by pinning all third-party actions to full commit SHAs and running OSSF Scorecard.
- **Credential leakage** – mitigated by secret scanning on every push and PR.
- **Pwn-request attacks** – mitigated by auditing all `pull_request_target` usages and forbidding checkout of untrusted PR head refs.
- **Script injection** – mitigated by CodeQL and Semgrep SAST rules.
- **Dependency vulnerabilities** – mitigated by Trivy and Dependency Review on every PR.
- **License compliance violations** – mitigated by automated license checks.

### Out-of-scope

- Physical security of infrastructure.
- Social engineering attacks targeting individual contributors.

## Security Best Practices for Contributors

1. **Never commit secrets** – use GitHub encrypted secrets or a secret manager.
2. **Pin all third-party actions** to a full commit SHA in workflow files.
3. **Use the principle of least privilege** – declare minimal `permissions:` in every workflow.
4. **Avoid `pull_request_target`** unless strictly necessary; never check out PR head code in that context.
5. **Sign your commits** using GPG or SSH keys.
6. **Keep dependencies up to date** – enable Dependabot or Renovate.
7. **Review SARIF results** in the Security → Code scanning tab after every push.

## Compliance

This repository's security program is designed to align with:

- [NIST Secure Software Development Framework (SSDF) SP 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [SLSA Framework (Supply-chain Levels for Software Artifacts)](https://slsa.dev/)
- [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide)
