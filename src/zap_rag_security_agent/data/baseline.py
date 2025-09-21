"""
Baseline Security Knowledge

OWASP Top 10 and other baseline security knowledge for the RAG security agent.
Provides foundational security concepts that the agent can reference during analysis.

This data is used to seed the ChromaDB vector memory with baseline security knowledge,
enabling the RAG agent to provide context-aware security analysis.
"""

BASELINE_DOCS = [
    """
    Injection vulnerabilities occur when untrusted data is passed to an interpreter, enabling the execution of unintended commands or queries. This is the most critical web application security risk according to OWASP Top 10.

    Common injection types include:
    - SQL Injection: Malicious SQL code inserted into database queries
    - NoSQL Injection: Similar to SQL injection but targeting NoSQL databases
    - Command Injection: Execution of arbitrary system commands
    - LDAP Injection: Manipulation of LDAP queries
    - XPath Injection: Exploitation of XPath queries

    How to detect:
    - Look for user input directly concatenated into queries
    - Check for special characters like quotes, semicolons, and comment symbols
    - Test with payloads like ' OR '1'='1, ; DROP TABLE users, etc.
    - Use tools like SQLMap, Burp Suite, or OWASP ZAP

    Mitigation strategies:
    - Use parameterized queries or prepared statements
    - Implement input validation and sanitization
    - Apply the principle of least privilege
    - Use stored procedures with proper parameterization
    - Implement proper error handling without information disclosure
    """,
    
    """
    Cross-Site Scripting (XSS) vulnerabilities occur when an attacker injects malicious scripts into web pages that are then executed in other users' browsers. This allows attackers to steal session cookies, deface websites, or redirect users to malicious sites.

    Types of XSS:
    - Reflected XSS: Malicious script is reflected off a web server
    - Stored XSS: Malicious script is permanently stored on the target server
    - DOM-based XSS: Vulnerability exists in client-side code

    How to detect:
    - Look for user input displayed without proper encoding
    - Check for dangerous JavaScript functions like innerHTML, document.write
    - Test with payloads like <script>alert('XSS')</script>
    - Use automated scanners like OWASP ZAP, Burp Suite, or Acunetix

    Mitigation strategies:
    - Encode all user input before displaying it
    - Implement Content Security Policy (CSP) headers
    - Use proper output encoding based on context (HTML, JavaScript, CSS, URL)
    - Validate and sanitize all user input
    - Use HTTP-only cookies to prevent script access
    """,
    
    """
    Broken Authentication refers to weaknesses in how applications manage authentication and session handling. This can lead to attackers impersonating users and bypassing authentication controls.

    Common authentication flaws:
    - Weak password policies and storage
    - Session fixation vulnerabilities
    - Insecure session management
    - Credential stuffing attacks
    - Brute force vulnerabilities
    - Insecure password recovery mechanisms

    How to detect:
    - Test for weak password requirements
    - Check for session management issues
    - Look for credential exposure in logs or error messages
    - Test for session fixation and hijacking
    - Verify proper logout functionality
    - Check for multi-factor authentication implementation

    Mitigation strategies:
    - Implement strong password policies
    - Use secure session management with random session IDs
    - Implement multi-factor authentication (MFA)
    - Use secure password hashing (bcrypt, Argon2, PBKDF2)
    - Implement account lockout mechanisms
    - Use HTTPS for all authentication-related communications
    """,
    
    """
    Sensitive Data Exposure occurs when sensitive data is improperly protected, risking exposure through weak encryption or insecure transmission. This includes financial data, healthcare information, and personally identifiable information (PII).

    Common sensitive data exposure scenarios:
    - Unencrypted sensitive data in transit or at rest
    - Weak encryption algorithms or implementations
    - Insecure key management
    - Data exposure in error messages or logs
    - Insecure data transmission over HTTP
    - Inadequate data retention policies

    How to detect:
    - Check for unencrypted data transmission
    - Verify encryption strength and implementation
    - Look for sensitive data in error messages
    - Check for data exposure in logs or debug information
    - Test for insecure direct object references
    - Verify proper data classification and handling

    Mitigation strategies:
    - Encrypt sensitive data both in transit and at rest
    - Use strong encryption algorithms (AES-256, RSA-2048+)
    - Implement proper key management
    - Use HTTPS/TLS for all data transmission
    - Implement data classification and handling policies
    - Regular security assessments and penetration testing
    """,
    
    """
    XML External Entities (XXE) vulnerabilities arise when an application fails to securely process XML input, allowing attackers to exploit external entities. This can lead to data exfiltration, denial of service attacks, or remote code execution.

    XXE attack vectors:
    - External entity references in XML documents
    - Billion Laughs attack (exponential entity expansion)
    - Local file inclusion through external entities
    - Server-Side Request Forgery (SSRF) via external entities
    - Blind XXE attacks for data exfiltration

    How to detect:
    - Test XML input processing with external entity references
    - Look for XXE vulnerabilities in XML parsers
    - Check for external entity processing in XML libraries
    - Test with XXE payloads in XML input
    - Use tools like OWASP ZAP or Burp Suite

    Mitigation strategies:
    - Disable external entity processing in XML parsers
    - Use JSON instead of XML where possible
    - Implement proper XML input validation
    - Use whitelist-based validation for XML schemas
    - Keep XML processing libraries updated
    - Implement proper error handling without information disclosure
    """,
    
    """
    Broken Access Control happens when a system allows users to perform unauthorized actions or access restricted resources. This is a critical security flaw that can lead to data breaches and unauthorized system access.

    Common access control flaws:
    - Insecure direct object references
    - Missing function level access control
    - Privilege escalation vulnerabilities
    - Insecure file and directory permissions
    - CORS misconfigurations
    - Missing authorization checks

    How to detect:
    - Test for direct object reference vulnerabilities
    - Check for missing authorization on sensitive functions
    - Test for privilege escalation opportunities
    - Verify proper access control implementation
    - Test for insecure file access
    - Check CORS configuration

    Mitigation strategies:
    - Implement Role-Based Access Control (RBAC)
    - Use proper authorization checks on all sensitive functions
    - Implement least privilege principle
    - Use indirect object references
    - Regular access control testing and auditing
    - Implement proper session management
    """,
    
    """
    Security Misconfiguration occurs when an application is poorly configured, often using default settings or leaving unnecessary services open. This can expose sensitive information or provide attack vectors.

    Common misconfiguration issues:
    - Default credentials and accounts
    - Unnecessary services and ports open
    - Insecure default configurations
    - Missing security headers
    - Verbose error messages
    - Outdated software and components

    How to detect:
    - Check for default credentials and accounts
    - Scan for unnecessary open ports and services
    - Verify security header implementation
    - Check for verbose error messages
    - Test for information disclosure
    - Verify software versions and updates

    Mitigation strategies:
    - Change all default credentials
    - Disable unnecessary services and ports
    - Implement proper security headers
    - Use secure configuration templates
    - Regular security configuration reviews
    - Keep software and components updated
    """,
    
    """
    Cross-Site Request Forgery (CSRF) takes advantage of the trust that a website has in a user's browser, tricking it into performing unintended actions. This can lead to unauthorized actions being performed on behalf of authenticated users.

    CSRF attack scenarios:
    - Unauthorized fund transfers
    - Password changes without user consent
    - Data modification or deletion
    - Account takeover
    - Administrative actions

    How to detect:
    - Check for missing CSRF tokens in forms
    - Test for CSRF vulnerabilities in state-changing operations
    - Verify CSRF protection implementation
    - Check for proper SameSite cookie attributes
    - Test for referrer header validation

    Mitigation strategies:
    - Implement CSRF tokens in all forms and state-changing operations
    - Use SameSite cookie attributes
    - Implement proper referrer header validation
    - Use double-submit cookie pattern
    - Implement custom headers for AJAX requests
    - Regular CSRF testing and validation
    """,
    
    """
    Using Components with Known Vulnerabilities means running outdated or unpatched libraries, frameworks, or modules that expose the system to known attacks. This is a common issue due to the complexity of modern applications and their dependencies.

    Common vulnerable components:
    - Outdated web frameworks (Struts, Spring, etc.)
    - Vulnerable JavaScript libraries (jQuery, Angular, React)
    - Outdated server software (Apache, Nginx, IIS)
    - Vulnerable database systems
    - Outdated operating system components
    - Vulnerable third-party plugins and modules

    How to detect:
    - Use dependency scanning tools (OWASP Dependency-Check, Snyk, Retire.js)
    - Regular vulnerability assessments
    - Monitor security advisories for used components
    - Implement automated dependency scanning
    - Regular penetration testing
    - Security code reviews

    Mitigation strategies:
    - Keep all components and dependencies updated
    - Use only trusted and actively maintained libraries
    - Implement automated dependency scanning
    - Regular security assessments
    - Use software composition analysis tools
    - Implement proper patch management processes
    """,
    
    """
    Insufficient Logging & Monitoring leaves systems vulnerable by failing to record critical actions, preventing early detection of attacks. This allows attackers to persist undetected and escalate their attacks.

    Common logging and monitoring gaps:
    - Missing or inadequate security event logging
    - Insufficient log retention policies
    - Lack of real-time monitoring and alerting
    - Inadequate log analysis and correlation
    - Missing audit trails for sensitive operations
    - Insufficient incident response capabilities

    How to detect:
    - Audit logging implementation and coverage
    - Check for log retention and storage policies
    - Verify monitoring and alerting systems
    - Test incident response procedures
    - Check for log analysis and correlation capabilities
    - Verify audit trail completeness

    Mitigation strategies:
    - Implement comprehensive security event logging
    - Use centralized logging and monitoring systems
    - Implement real-time alerting for security events
    - Regular log analysis and correlation
    - Implement proper incident response procedures
    - Use Security Information and Event Management (SIEM) systems
    """
]
