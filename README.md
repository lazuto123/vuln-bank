# CI/CD Security Pipeline for vuln-bank

This repository is a fork of the original **vuln-bank** project with the addition of a **Jenkinsfile** for automated **CI/CD pipeline** that focuses on **security scanning**.  
The pipeline is designed to detect **secrets, vulnerable dependencies, code issues, misconfigurations, OS hardening compliance, and runtime vulnerabilities (DAST)**.

---

## 🔧 Pipeline Architecture & Workflow

The pipeline follows this workflow:

```mermaid
graph TD
  A["Checkout Source Code"] --> B["Secret Scanning (TruffleHog)"]
  B --> C["SCA with Snyk"]
  C --> D["SAST with Snyk Code"]
  D --> E["Misconfiguration Scanning (Checkov)"]
  E --> F["OS Hardening (Ansible)"]
  F --> G["Deployment with Docker Compose"]
  G --> H["DAST with OWASP ZAP"]
  H --> I["Notification via Email"]
```

---

## 🛠️ Tools Used

| Tool / Framework | Purpose in Pipeline |
|------------------|---------------------|
| **TruffleHog**   | Secret scanning – detects leaked API keys, tokens, and credentials in code. |
| **Snyk SCA**     | Software Composition Analysis – scans Python dependencies for vulnerabilities. |
| **Snyk SAST**    | Static Application Security Testing – analyzes Python source code for bugs and security risks. |
| **Checkov**      | Misconfiguration scanning – checks Dockerfile and IaC misconfigurations. |
| **Ansible (dev-sec.os-hardening)** | Server OS hardening and compliance enforcement. |
| **OWASP ZAP**    | Dynamic Application Security Testing (DAST) – scans the running web application. |
| **Jenkins**      | CI/CD orchestrator for executing the pipeline. |
| **Email Notification (emailext)** | Sends alerts if critical/high vulnerabilities are found. |

---

## 🚨 Handling Critical Findings

The pipeline collects reports from each tool in **JSON/XML/HTML** formats.  
When **High or Critical findings** are detected:

- Pipeline marks the stage with security issues.  
- Adds the findings to a short summary.  
- Sends **email notification** to the communication channel (`brigaup987@gmail.com`).  
- Full details can be reviewed in the Jenkins artifacts (JSON/XML/HTML scan reports).  

If **no High/Critical findings** are present, the pipeline proceeds normally without sending an email.

---

## 📌 To-Do List

The following tasks are still pending or need improvements:

- [ ] **Email Notifications**: Email body only shows TruffleHog findings, not full details from Snyk, Checkov, or ZAP.  
- [ ] **Hardening & Compliance Checks**: Ansible hardening role is not yet running smoothly in the pipeline.  
- [ ] **Misconfiguration Scanning**: Checkov reports are not fully integrated into the findings.  
- [ ] **Additional SAST with LLM**: Integrate LLM-based code analysis to detect logical vulnerabilities.  
- [ ] **Integration with Vulnerability Manager**: Not yet connected to a vulnerability management platform (e.g., DefectDojo, Faraday, or Jira).  

---

## 📎 Notes

- This pipeline is still under active development.  
- The end goal is to achieve a **comprehensive end-to-end security CI/CD pipeline** that can automatically detect, report, and manage vulnerabilities.  

---

## 🛠️ Mermaid troubleshooting (if GitHub can't render)

If GitHub does not render the chart, try the following:

- Ensure the block starts with three backticks and `mermaid` on the same line: ```mermaid
- Use `graph TD` instead of `flowchart TD` (some renderers prefer `graph`).  
- Quote node labels like `A["Label (with parentheses)"]` to avoid parsing issues.  
- Avoid special control characters in labels.  
- If still failing, check whether your repository has Mermaid support enabled or try viewing the README in a different browser or via VS Code preview.

