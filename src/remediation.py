"""Deterministic guidance shared by synthetic generation and future assistants."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Guidance:
    cwe_id: str
    component: str
    description: str
    remediation: str


# First matching rule wins; narrower vulnerability types precede general ones.
RULES = (
    (("sql injection",), Guidance("CWE-89", "query_layer", "Untrusted input can alter database queries.", "Use parameterized queries and restrict database permissions.")),
    (("cross-site scripting",), Guidance("CWE-79", "web_templates", "Untrusted content can execute in a user's browser.", "Apply context-aware output encoding and sanitize permitted HTML.")),
    (("command injection",), Guidance("CWE-78", "report_runner", "Untrusted input can alter operating system commands.", "Avoid shell execution; use safe APIs and allowlisted arguments.")),
    (("deserialization",), Guidance("CWE-502", "serialization", "Untrusted serialized objects can trigger unsafe behavior.", "Use safe data formats and reject untrusted object deserialization.")),
    (("path traversal",), Guidance("CWE-22", "file_export", "User-controlled paths can access unintended files.", "Normalize paths and enforce an allowlisted base directory.")),
    (("server-side request forgery",), Guidance("CWE-918", "http_client", "User-controlled destinations can reach unintended services.", "Allowlist destinations and block internal network addresses.")),
    (("cross-site request forgery",), Guidance("CWE-352", "request_handler", "State-changing requests may lack origin verification.", "Require CSRF tokens and validate request origins.")),
    (("cors",), Guidance("CWE-942", "cors_policy", "Cross-origin access may be broader than intended.", "Allowlist trusted origins and restrict credentialed cross-origin requests.")),
    (("session fixation",), Guidance("CWE-384", "session_manager", "Session identifiers may survive authentication transitions.", "Rotate session IDs after authentication and privilege changes.")),
    (("authentication bypass", "unauthenticated management"), Guidance("CWE-306", "authentication", "Sensitive functionality may be reachable without authentication.", "Enforce authentication on sensitive endpoints and restrict management access.")),
    (("authorization",), Guidance("CWE-862", "authorization", "Sensitive operations may lack permission checks.", "Enforce server-side authorization for each operation and resource.")),
    (("signature verification",), Guidance("CWE-347", "token_verifier", "Invalid signatures may be accepted by token verification.", "Upgrade the token library and enforce signature and algorithm validation.")),
    (("regular expression",), Guidance("CWE-1333", "text_parser", "Expensive patterns may exhaust processing resources.", "Upgrade the parser, bound input size, and use linear-time patterns.")),
    (("denial of service",), Guidance("CWE-400", "http_transport", "Unbounded resource use may interrupt service availability.", "Upgrade the affected package and apply resource and request limits.")),
    (("remote code execution",), Guidance("CWE-94", "runtime", "A vulnerable component may allow unintended code execution.", "Apply the vendor security update and restrict exposure until patched.")),
    (("tls",), Guidance("CWE-326", "tls_configuration", "Legacy encryption settings may weaken transport security.", "Disable legacy TLS protocols and apply a supported secure configuration baseline.")),
    (("unsupported operating",), Guidance("CWE-1104", "operating_system", "Unsupported software may no longer receive security fixes.", "Migrate to a supported operating system and apply current security updates.")),
    (("outdated ssh",), Guidance("CWE-1104", "ssh_service", "An outdated network service may contain unpatched weaknesses.", "Upgrade the SSH package and restrict management access.")),
    (("network service",), Guidance("CWE-16", "network_configuration", "An unnecessary service increases the exposed attack surface.", "Disable unnecessary services and apply restrictive network access rules.")),
    (("content-security-policy",), Guidance("CWE-693", "response_headers", "A missing browser policy reduces defense in depth.", "Configure and test a restrictive Content-Security-Policy.")),
    (("x-content-type-options",), Guidance("CWE-693", "response_headers", "Browsers may interpret content using unintended MIME types.", "Set X-Content-Type-Options to nosniff on relevant responses.")),
    (("temporary file",), Guidance("CWE-377", "temporary_storage", "Temporary artifacts may have unsafe access permissions.", "Upgrade the utility package and use securely created temporary files.")),
    (("disclosure", "exposed in logs", "error message", "banner"), Guidance("CWE-200", "diagnostics", "Diagnostic output may reveal unnecessary internal information.", "Remove sensitive diagnostics and limit public error and version details.")),
)
SECRET_GUIDANCE = Guidance(
    "CWE-798", "demo_settings", "A fictional credential is stored outside a secrets manager.",
    "Rotate any affected credentials, remove them from source and history, and use a secrets manager.",
)
DEPENDENCY_GUIDANCE = Guidance(
    "CWE-1395", "dependency_package", "A dependency is modeled as having a known weakness.",
    "Upgrade the affected dependency to a patched release and rerun dependency checks.",
)
DEFAULT_GUIDANCE = Guidance(
    "CWE-16", "security_configuration", "A synthetic configuration weakness needs review.",
    "Apply a secure configuration baseline and verify the affected control.",
)


def get_guidance(vulnerability_name: str, tool: str = "") -> Guidance:
    """Return advice, never a claim that a fix has been applied or verified."""
    if tool == "QWIET-SECRETS":
        return SECRET_GUIDANCE
    name = vulnerability_name.casefold()
    for keywords, guidance in RULES:
        if any(keyword in name for keyword in keywords):
            if tool == "Corona SCA":
                return Guidance(
                    guidance.cwe_id, guidance.component, guidance.description,
                    f"Upgrade the affected dependency to a patched release. {guidance.remediation}",
                )
            return guidance
    if tool == "Corona SCA":
        return DEPENDENCY_GUIDANCE
    return DEFAULT_GUIDANCE
