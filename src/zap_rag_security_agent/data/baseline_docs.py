BASELINE_DOCS = [
    {
        "id": "baseline_1",
        "content": "Injection vulnerabilities occur when untrusted data is passed to an interpreter, enabling the execution of unintended commands or queries.",
        "metadata": {
            "category": "baseline",
            "tags": ["injection", "sql", "nosql", "os", "ldap"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_2",
        "content": "Cross-Site Scripting (XSS) vulnerabilities occur when an attacker injects malicious scripts into web pages that are then executed in other users' browsers.",
        "metadata": {
            "category": "baseline",
            "tags": ["xss", "script", "vulnerabilities"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_3",
        "content": "Broken Authentication refers to weaknesses in how applications manage authentication and session handling.",
        "metadata": {
            "category": "baseline",
            "tags": ["authentication", "session", "security"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_4",
        "content": "Sensitive Data Exposure occurs when sensitive data is improperly protected, risking exposure through weak encryption or insecure transmission.",
        "metadata": {
            "category": "baseline",
            "tags": ["data protection", "encryption", "privacy"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_5",
        "content": "XML External Entities (XXE) vulnerabilities arise when an application fails to securely process XML input, allowing attackers to exploit external entities.",
        "metadata": {
            "category": "baseline",
            "tags": ["xxe", "xml", "entities"],
            "source": "OWASP Top 10 2021",
            "severity": "medium"
        }
    },
    {
        "id": "baseline_6",
        "content": "Broken Access Control happens when a system allows users to perform unauthorized actions or access restricted resources.",
        "metadata": {
            "category": "baseline",
            "tags": ["access control", "permissions", "security"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_7",
        "content": "Security Misconfiguration occurs when an application is poorly configured, often using default settings or leaving unnecessary services open.",
        "metadata": {
            "category": "baseline",
            "tags": ["misconfiguration", "configuration", "security"],
            "source": "OWASP Top 10 2021",
            "severity": "medium"
        }
    },
    {
        "id": "baseline_8",
        "content": "Cross-Site Request Forgery (CSRF) takes advantage of the trust that a website has in a user's browser, tricking it into performing unintended actions.",
        "metadata": {
            "category": "baseline",
            "tags": ["csrf", "request forgery", "attack"],
            "source": "OWASP Top 10 2021",
            "severity": "medium"
        }
    },
    {
        "id": "baseline_9",
        "content": "Using Components with Known Vulnerabilities means running outdated or unpatched libraries, exposing the system to known attacks.",
        "metadata": {
            "category": "baseline",
            "tags": ["components", "vulnerabilities", "security"],
            "source": "OWASP Top 10 2021",
            "severity": "high"
        }
    },
    {
        "id": "baseline_10",
        "content": "Insufficient Logging & Monitoring leaves systems vulnerable by failing to record critical actions, preventing early detection of attacks.",
        "metadata": {
            "category": "baseline",
            "tags": ["logging", "monitoring", "security"],
            "source": "OWASP Top 10 2021",
            "severity": "medium"
        }
    }
]


# BASELINE_DOCS = [
#     """
#     Injection (SQL, NoSQL, OS, LDAP):
#     -------------------------------
#     What is it? 
#     Injection vulnerabilities occur when untrusted data is sent to an interpreter as part of a command or query.

#     How does it work?
#     - Attackers can inject malicious commands that are executed by the server, potentially causing data exposure, data manipulation, or system compromise.

#     Why is it dangerous?
#     - Attackers can modify queries, read or delete data, execute system commands, or escalate privileges.

#     How to detect it?
#     - Use tools like SQLMap, Burp Suite, or OWASP ZAP to test for injection vulnerabilities.
    
#     Mitigation:
#     - Use parameterized queries or prepared statements (e.g., with SQLAlchemy or Hibernate).
#     - Validate and sanitize all user inputs.

#     Example exploit:
#     - SQL Injection: Input `'; DROP TABLE users; --` in a search box can delete all users.
#     """,
#     """
#     Cross-Site Scripting (XSS):
#     -------------------------
#     What is it? 
#     XSS vulnerabilities occur when an attacker injects malicious scripts into webpages viewed by other users.

#     How does it work?
#     - Attackers can exploit vulnerabilities where user input is displayed without proper sanitization, causing scripts to execute in users' browsers.

#     Why is it dangerous?
#     - Attackers can steal session cookies, deface websites, or redirect users to malicious sites.

#     How to detect it?
#     - Tools like OWASP ZAP, Burp Suite or Acunetix can detect XSS vulnerabilities.
    
#     Mitigation:
#     - Sanitize user inputs and use Content Security Policy (CSP) headers.
#     - Encode outputs properly to avoid script execution in browsers.

#     Example exploit:
#     - Stored XSS: A comment form allows an attacker to inject `<script>alert('XSS')</script>`, which executes when other users view the comment.
#     """,
#     """
#     Broken Authentication:
#     -----------------------
#     What is it? 
#     Insecure implementation of authentication and session management.

#     How does it work?
#     - Attackers exploit poor session management to impersonate users and bypass authentication controls.

#     Why is it dangerous?
#     - Attackers can steal user credentials, session tokens, or perform unauthorized actions as a legitimate user.

#     How to detect it?
#     - Ensure that multi-factor authentication (MFA) is implemented, and session tokens are protected (e.g., HttpOnly, Secure flags).
    
#     Mitigation:
#     - Use strong authentication mechanisms like OAuth2, JWT, and MFA.
#     - Use secure, randomly generated session identifiers and ensure secure session management.

#     Example exploit:
#     - Session Hijacking: An attacker steals a valid session cookie through XSS and impersonates a user.
#     """,
#     """
#     Sensitive Data Exposure:
#     -------------------------
#     What is it? 
#     Applications or APIs not properly protecting sensitive data, such as financial, healthcare, or PII information.

#     How does it work?
#     - Attackers can exploit weak encryption, poor key management, or lack of secure transport to access sensitive data.

#     Why is it dangerous?
#     - Sensitive data can be exposed, leading to financial loss, identity theft, or privacy violations.

#     How to detect it?
#     - Ensure that sensitive data is encrypted using strong encryption standards, like AES-256.
    
#     Mitigation:
#     - Use TLS/SSL for data transmission.
#     - Encrypt sensitive data both in transit and at rest.

#     Example exploit:
#     - Weak Encryption: An attacker intercepts unencrypted traffic between the client and the server and extracts sensitive information like passwords or credit card numbers.
#     """,
#     """
#     XML External Entities (XXE):
#     -------------------------
#     What is it? 
#     XXE vulnerabilities occur when applications process XML input without disabling entity references.

#     How does it work?
#     - Attackers can inject malicious XML that points to an external entity, potentially leading to data exfiltration or remote code execution.

#     Why is it dangerous?
#     - Attackers can read files, perform denial-of-service attacks, or execute code remotely.

#     How to detect it?
#     - OWASP ZAP and Burp Suite can be used to detect XXE vulnerabilities.

#     Mitigation:
#     - Disable external entity processing in XML parsers (e.g., by setting `XMLParser.DISALLOW_DOCTYPE_DECL` to `True`).
#     - Use JSON instead of XML where possible.

#     Example exploit:
#     - XXE Injection: An attacker sends a crafted XML payload to read sensitive files like `/etc/passwd` on the server.
#     """,
#     """
#     Broken Access Control:
#     ----------------------
#     What is it? 
#     Broken access control occurs when users are allowed to perform actions beyond their authorized permissions.

#     How does it work?
#     - Attackers can bypass restrictions and act as other users or admins.

#     Why is it dangerous?
#     - Unauthorized access can lead to data leakage, data manipulation, or privilege escalation.

#     How to detect it?
#     - Test for improper access control by attempting to escalate privileges or access restricted resources.
    
#     Mitigation:
#     - Use Role-Based Access Control (RBAC) to enforce access restrictions.
#     - Always validate user roles on the server-side before processing sensitive operations.

#     Example exploit:
#     - Privilege Escalation: An attacker changes the `role` parameter in a URL to access admin resources.
#     """,
#     """
#     Security Misconfiguration:
#     ---------------------------
#     What is it? 
#     Applications with incomplete setups, default configurations, or misconfigured HTTP headers expose themselves to vulnerabilities.

#     How does it work?
#     - Attackers can exploit default credentials, unprotected services, or exposed unnecessary ports.

#     Why is it dangerous?
#     - Security misconfigurations can lead to unauthorized access or exposure of sensitive information.

#     How to detect it?
#     - Perform a thorough configuration review and vulnerability scan using tools like Nessus or Qualys.
    
#     Mitigation:
#     - Securely configure all components (servers, databases, APIs).
#     - Regularly audit your security configuration.

#     Example exploit:
#     - Default Credentials: An attacker uses default admin credentials (`admin:admin`) to gain access to the admin panel.
#     """,
#     """
#     Cross-Site Request Forgery (CSRF):
#     --------------------------------
#     What is it? 
#     CSRF exploits the trust that a web application has in the user's browser, tricking it into making requests on behalf of an attacker.

#     How does it work?
#     - The attacker can trick the victim into performing unintended actions (e.g., changing their password) by making a request from a malicious website.

#     Why is it dangerous?
#     - Attackers can hijack authenticated sessions and perform actions without the victim's consent.

#     How to detect it?
#     - Check for missing CSRF tokens in forms or API requests.

#     Mitigation:
#     - Implement CSRF tokens in forms and API requests.
#     - Use SameSite cookie attributes and enforce Referer header checks.

#     Example exploit:
#     - Changing Password: An attacker sends a victim a malicious email link that changes their password without their consent.
#     """,
#     """
#     Using Components with Known Vulnerabilities:
#     ------------------------------------------
#     What is it? 
#     Using outdated or unpatched components exposes the application to known vulnerabilities.

#     How does it work?
#     - Attackers exploit vulnerabilities in outdated libraries, frameworks, or modules to compromise the application.

#     Why is it dangerous?
#     - Known vulnerabilities are often publicly documented, making it easy for attackers to exploit them.

#     How to detect it?
#     - Regularly check your dependencies for vulnerabilities using tools like OWASP Dependency-Check, Snyk, or Retire.js.

#     Mitigation:
#     - Keep software components up-to-date.
#     - Use only trusted and actively maintained libraries.

#     Example exploit:
#     - Outdated Framework: An attacker exploits a vulnerability in Apache Struts (CVE-2017-5638) to perform remote code execution.
#     """,
#     """
#     Insufficient Logging & Monitoring:
#     ---------------------------------
#     What is it? 
#     Insufficient logging and monitoring leave applications vulnerable to undetected attacks.

#     How does it work?
#     - Without adequate logging, attackers can carry out prolonged attacks without detection.

#     Why is it dangerous?
#     - Insufficient monitoring allows attackers to persist undetected, escalate attacks, or avoid forensic analysis.

#     How to detect it?
#     - Perform security audits to ensure logging is enabled for all critical actions and events.

#     Mitigation:
#     - Implement centralized logging and set up alerts for suspicious activities.
#     - Use tools like ELK Stack or Splunk for real-time monitoring and analysis.

#     Example exploit:
#     - Lack of Monitoring: An attacker injects a malicious script into a form, and there’s no log of the attack or abnormal behavior to detect it.
#     """
# ]
