# v1
# preprocess.py

"""
Type-aware preprocessing utilities for traffic chunks.

Functions:
 - normalize_chunk_text(chunk_text: str, chunk_type: str) -> (normalized_text:str, meta:dict)
 - redact_sensitive_headers(headers_text: str) -> str
 - safe_base64_decode_if_text(s: str) -> (decoded_str, decoded_bool)

Normalization is intentionally conservative: prefer not to destroy forensic data,
but normalize encodings and redact sensitive tokens (session ids, auth tokens).
"""

import urllib.parse
import html
import re
import base64
import json
from typing import Tuple, Dict, List
from ..detectors.stack_detector import detect_stack_from_traffic

# Patterns of keys/values to redact from headers/query/body when found
SENSITIVE_KEYWORDS = [
    "authorization",
    "authorization:",
    "authorization-bearer",
    "bearer",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "session",
    "jsessionid",
    "phpsessid",
    "set-cookie",
    "cookie",
    "x-api-key",
]

# regexes to detect likely API keys / long hex tokens
TOKEN_RE = re.compile(r"(?P<key>[a-z0-9_-]{8,})(?P<maybe>[\-_.]?[A-Za-z0-9\-_.]{8,})")

# common suspicious patterns to flag heuristically
SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(r"(\bunion\b|\bor\b\s+1=1|\bselect\b.*\bfrom\b|--|;--|;|\bexec\b|\bsleep\()", re.I),
    "cmd_injection": re.compile(r"[;&|`$()]\s*|(\b(popen|system|exec|passthru)\b)", re.I),
    "xss": re.compile(r"<script\b|javascript:|onerror=|onload=", re.I),
}

# heuristics for binary detection: presence of many null bytes or non-text bytes
def looks_binary(b: bytes) -> bool:
    if not b:
        return False
    # If null bytes present, treat as binary
    if b.count(b"\x00") > 0:
        return True
    # If more than 30% non-printable bytes, treat as binary
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
    non_text = sum(ch not in text_chars for ch in b)
    return (non_text / len(b)) > 0.30

def safe_base64_decode_if_text(s: str):
    """
    If s looks like base64 and decodes to readable text, return (decoded_text, True).
    Otherwise return (original, False).
    """
    # quick sanity checks
    s_clean = s.strip()
    # must be multiple of 4 and only base64 chars (allow urlsafe too)
    if len(s_clean) < 16:
        return s, False
    # if re.fullmatch(r"[A-Za-z0-9+/_=-\s]+", s_clean) is None:
    if re.fullmatch(r"[A-Za-z0-9+/_=\s-]+", s_clean) is None:
        return s, False

    # remove whitespace/newlines
    candidate = re.sub(r"\s+", "", s_clean)
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except Exception:
        try:
            decoded = base64.urlsafe_b64decode(candidate)
        except Exception:
            return s, False

    try:
        if looks_binary(decoded):
            return s, False
        text = decoded.decode("utf-8", errors="replace")
        # small heuristic: if decoded text has many printable characters, accept
        printable_ratio = sum(1 for ch in text if ch.isprintable()) / max(1, len(text))
        if printable_ratio > 0.7:
            return text, True
        return s, False
    except Exception:
        return s, False

def redact_value(value: str) -> str:
    """Redact tokens that match common token patterns or keys."""
    if not value:
        return value
    v = value
    # redact long hex-like tokens
    v = re.sub(r"([A-Fa-f0-9]{8,})([A-Fa-f0-9\-_.]{8,})?", "[REDACTED_TOKEN]", v)
    # redact sequences that look like jwt (header.payload.signature)
    v = re.sub(r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "[REDACTED_JWT]", v)
    return v

def redact_sensitive_headers(headers_text: str) -> str:
    lines = []
    for line in headers_text.splitlines():
        if ":" not in line:
            lines.append(line)
            continue
        k, v = line.split(":", 1)
        k_lower = k.strip().lower()
        if any(k_partial in k_lower for k_partial in SENSITIVE_KEYWORDS):
            lines.append(f"{k}: [REDACTED]")
            continue
        # redact values heuristically
        redacted_val = redact_value(v.strip())
        lines.append(f"{k}: {redacted_val}")
    return "\n".join(lines)

def normalize_query_string(query: str):
    """
    Decode URL-encoded query into canonical "k=v" lines, redacting values as needed.
    Returns: canonical_str, params_count, redacted_preview
    """
    if not query:
        return "", 0, ""
    try:
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except Exception:
        # fallback: treat raw string
        s = urllib.parse.unquote_plus(query)
        return s, 0, ""

    lines = []
    for k, v in params:
        k_norm = k.strip().lower()
        v_decoded = urllib.parse.unquote_plus(v)
        v_redacted = v_decoded
        if any(kpart in k_norm for kpart in SENSITIVE_KEYWORDS):
            v_redacted = "[REDACTED]"
        else:
            v_redacted = redact_value(v_decoded)
        lines.append(f"{k_norm}={v_redacted}")
    return "\n".join(lines), len(params), ",".join([k for k, _ in params][:5])

def normalize_path(path: str):
    """
    Normalize path: URL decode, strip long ids, lower-case, truncate long path segments.
    """
    if not path:
        return ""
    try:
        p = urllib.parse.unquote(path)
    except Exception:
        p = path
    p = html.unescape(p)
    p = p.strip()
    # collapse multiple slashes
    p = re.sub(r"/{2,}", "/", p)
    # truncate long numeric/hex segments to keep semantic tokens
    def truncate_segment(seg):
        if len(seg) > 64:
            return seg[:16] + "...[" + str(len(seg)) + "]"
        return seg
    parts = [truncate_segment(seg) for seg in p.split("/")]
    p2 = "/".join(parts)
    return p2.lower()

def normalize_body(body: str):
    """
    Heuristic normalization for body:
     - Try to detect JSON and pretty-print (with sorted keys)
     - If form-encoded, decode similarly to query params
     - Try base64 decode if candidate
     - Redact sensitive-looking keys
    """
    if not body:
        return ""
    b = body.strip()

    # try JSON
    try:
        parsed = json.loads(b)
        # redact sensitive keys at top-level (shallow)
        if isinstance(parsed, dict):
            for k in list(parsed.keys()):
                if any(sk in k.lower() for sk in SENSITIVE_KEYWORDS):
                    parsed[k] = "[REDACTED]"
        pretty = json.dumps(parsed, sort_keys=True)
        return pretty
    except Exception:
        pass

    # try form-encoded
    if "=" in b and "&" in b and "%" in b:
        try:
            qs, _, _ = normalize_query_string(b)
            return qs
        except Exception:
            pass

    # try base64 decode
    decoded, ok = safe_base64_decode_if_text(b)
    if ok:
        return decoded

    # fallback: url-decode + redact values heuristically
    try:
        s = urllib.parse.unquote_plus(b)
    except Exception:
        s = b
    s = html.unescape(s)
    s = redact_value(s)
    # collapse whitespace
    s = re.sub(r"\s+", " ", s)
    return s

# Main exported function
def preprocess_payload(text: str, chunk_type: str = None):
    """
    Normalize a payload depending on chunk_type.
    Returns normalized_text (str).
    chunk_type in {'path', 'query', 'headers', 'body'} or None.
    """
    if text is None:
        return ""

    if chunk_type == "path":
        return normalize_path(text)
    if chunk_type == "query":
        qs, count, preview = normalize_query_string(text)
        return qs
    if chunk_type == "headers":
        return redact_sensitive_headers(text)
    if chunk_type == "body":
        # body normalization may be heavier
        return normalize_body(text)
    # fallback: generic decode + collapse
    try:
        s = urllib.parse.unquote_plus(text)
    except Exception:
        s = text
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s)
    return s


# -------------------------
# Suspicion / annotation helpers
# -------------------------
def compute_suspicion_score(text: str) -> Tuple[int, List[str]]:
    """
    Return (score, matched_tags)
    Score is a lightweight sum — you can tune weights per pattern.
    matched_tags is list of pattern keys that matched.
    """
    if not text:
        return 0, []

    score = 0
    matched = []

    # weights: higher weight for command-injection tokens
    weights = {
        "sql_injection": 2,
        "cmd_injection": 3,
        "xss": 2,
    }

    for tag, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(text):
            matched.append(tag)
            score += weights.get(tag, 1)

    # small extra heuristics
    # many shell metachars -> bump score
    if re.search(r"[;&|`$()<>]{2,}", text):
        score += 1

    return score, matched


def annotate_suspicious_tokens(text: str) -> str:
    """
    Non-destructively annotate suspicious tokens with [ATTACK:token] markers.
    This is conservative: we only replace the exact matched substrings.
    """
    if not text:
        return text

    # For each pattern, mark occurrences. Use a safe replacer that avoids infinite loops.
    out = text

    def mark_matches(pattern, marker_prefix):
        nonlocal out
        def repl(m):
            s = m.group(0)
            # don't double-mark
            if "[ATTACK:" in s:
                return s
            # limit length of marker content to avoid long markers
            label = s if len(s) <= 40 else s[:37] + "..."
            return f"[ATTACK:{label}]"
        try:
            out = pattern.sub(repl, out)
        except re.error:
            pass

    # Mark command injection tokens heuristically first (higher signal)
    cmd_pattern = SUSPICIOUS_PATTERNS.get("cmd_injection")
    if cmd_pattern:
        mark_matches(cmd_pattern, "CMD")

    sql_pattern = SUSPICIOUS_PATTERNS.get("sql_injection")
    if sql_pattern:
        mark_matches(sql_pattern, "SQL")

    xss_pattern = SUSPICIOUS_PATTERNS.get("xss")
    if xss_pattern:
        mark_matches(xss_pattern, "XSS")

    return out


def normalize_chunk_text(chunk_text: str, chunk_type: str = None) -> Tuple[str, Dict]:
    """
    Higher-level normalizer used by collectors:
      - Calls preprocess_payload(chunk_text, chunk_type) to get normalized text
      - Computes suspicion_score and matched tags
      - Performs stack detection for headers and HTML content
      - Optionally annotates suspicious tokens in the normalized text
    Returns:
      (normalized_text, meta_dict)
        meta_dict contains:
          - suspicion_score: int
          - suspicious_tags: list[str]
          - suspicious: bool (score > 0)
          - stack_detection: dict (if applicable)
    """
    # Handle None input
    if chunk_text is None:
        chunk_text = ""
    
    # keep the original normalization
    normalized = preprocess_payload(chunk_text, chunk_type)

    # compute suspicion
    score, tags = compute_suspicion_score(normalized)

    # annotate text for easier inspection (keeps original content)
    annotated = annotate_suspicious_tokens(normalized) if score > 0 else normalized

    meta = {
        "suspicion_score": int(score),
        "suspicious": bool(score > 0),
        "suspicious_tags": tags,
        "chunk_type": chunk_type or "unknown"
    }

    # Perform stack detection for headers and HTML content
    if chunk_type in ["headers", "body"] and chunk_text.strip():
        try:
            if chunk_type == "headers":
                stack_result = detect_stack_from_traffic(headers_text=chunk_text)
            elif chunk_type == "body":
                # Check if body contains HTML
                if "<html" in chunk_text.lower() or "<!doctype" in chunk_text.lower():
                    stack_result = detect_stack_from_traffic(html_content=chunk_text)
                else:
                    # Check if it's POST data
                    if chunk_text.strip().startswith('{') or '=' in chunk_text and '&' in chunk_text:
                        stack_result = detect_stack_from_traffic(post_data=chunk_text)
                    else:
                        stack_result = {}
            else:
                stack_result = {}
            
            # Add stack detection results to metadata (flattened for JSON safety)
            if stack_result and stack_result.get("total_detected", 0) > 0:
                meta["stack_detection"] = {
                    "total_detected": stack_result.get("total_detected", 0),
                    "confidence": stack_result.get("confidence", 0.0),
                    "detection_methods": stack_result.get("detection_methods", []),
                    "has_standard_libs": len(stack_result.get("standard_libraries", [])) > 0,
                    "has_custom_libs": len(stack_result.get("custom_libraries", [])) > 0
                }
                
                # Add top component if available
                top_component = stack_result.get("top_component")
                if top_component:
                    meta["top_component"] = {
                        "name": top_component.get("name", ""),
                        "version": top_component.get("version", ""),
                        "type": top_component.get("type", ""),
                        "confidence": top_component.get("confidence", 0.0),
                        "is_vulnerable": top_component.get("vulnerability_check", {}).get("is_vulnerable", False)
                    }
                
                # Add component candidates (flattened)
                component_candidates = stack_result.get("component_candidates", [])
                if component_candidates:
                    meta["component_candidates"] = json.dumps([
                        {
                            "name": comp.get("name", ""),
                            "version": comp.get("version", ""),
                            "category": comp.get("category", ""),
                            "confidence": comp.get("confidence", 0.0),
                            "is_vulnerable": comp.get("vulnerability_check", {}).get("is_vulnerable", False)
                        }
                        for comp in component_candidates[:10]  # Limit to first 10
                    ])
                
                # Add security analysis
                security_analysis = stack_result.get("security_analysis", {})
                if security_analysis:
                    meta["security_analysis"] = {
                        "total_security_issues": security_analysis.get("total_security_issues", 0),
                        "high_severity_issues": security_analysis.get("high_severity_issues", 0),
                        "medium_severity_issues": security_analysis.get("medium_severity_issues", 0),
                        "security_risk_score": security_analysis.get("security_risk_score", 0),
                        "has_vulnerabilities": security_analysis.get("has_vulnerabilities", False),
                        "has_credentials": security_analysis.get("credential_analysis", {}).get("has_credentials", False),
                        "has_post_attacks": security_analysis.get("post_data_analysis", {}).get("has_attacks", False)
                    }
                    
                    # Add security issues summary (flattened)
                    security_issues = security_analysis.get("security_issues", [])
                    if security_issues:
                        meta["security_issues_summary"] = json.dumps([
                            {
                                "type": issue.get("type", ""),
                                "severity": issue.get("severity", ""),
                                "description": issue.get("description", issue.get("reason", ""))[:100]
                            }
                            for issue in security_issues[:5]  # Limit to first 5
                        ])
                
        except Exception as e:
            # Don't fail the entire process if stack detection fails
            meta["stack_detection_error"] = str(e)

    return annotated, meta


# v2
# preprocess.py
# """
# Type-aware preprocessing utilities for traffic chunks.

# Functions:
#  - normalize_chunk_text(chunk_text: str, chunk_type: str) -> (normalized_text:str, meta:dict)
#  - redact_sensitive_headers(headers_text: str) -> str
#  - safe_base64_decode_if_text(s: str) -> (decoded_str: str, decoded_bool)

# Detectors:
#  - Suspicious payload patterns (SQLi, CMDi, XSS)
#  - Credential leaks (API keys, JWTs, tokens, passwords)

# Normalization is intentionally conservative:
# prefer not to destroy forensic data, but normalize encodings
# and redact sensitive tokens (session ids, auth tokens).
# """

# import urllib.parse
# import html
# import re
# import base64
# import json

# # ===========================
# # Redaction Config
# # ===========================

# SENSITIVE_KEYWORDS = [
#     "authorization", "authorization:", "authorization-bearer",
#     "bearer", "api_key", "apikey", "api-key", "token", "session",
#     "jsessionid", "phpsessid", "set-cookie", "cookie", "x-api-key",
# ]

# TOKEN_RE = re.compile(r"(?P<key>[a-z0-9_-]{8,})(?P<maybe>[\-_.]?[A-Za-z0-9\-_.]{8,})")

# # ===========================
# # Suspicious Pattern Detectors
# # ===========================

# SUSPICIOUS_PATTERNS = {
#     "sql_injection": re.compile(
#         r"(\bunion\b|\bor\b\s+1=1|\bselect\b.*\bfrom\b|--|;--|;|\bexec\b|\bsleep\()",
#         re.I,
#     ),
#     "cmd_injection": re.compile(
#         r"[;&|`$()]\s*|(\b(popen|system|exec|passthru)\b)",
#         re.I,
#     ),
#     "xss": re.compile(
#         r"<script\b|javascript:|onerror=|onload=",
#         re.I,
#     ),
# }

# CREDENTIAL_PATTERNS = {
#     "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
#     "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
#     "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
#     "github_pat": re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}"),
#     "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-_.=]+"),
#     "jwt": re.compile(
#         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"
#     ),
#     "generic_hex_token": re.compile(r"\b[a-f0-9]{32,64}\b"),
#     "password_field": re.compile(
#         r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?.{4,}['\"]?"
#     ),
# }

# # ===========================
# # Helpers
# # ===========================

# def looks_binary(b: bytes) -> bool:
#     if not b:
#         return False
#     if b.count(b"\x00") > 0:
#         return True
#     text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
#     non_text = sum(ch not in text_chars for ch in b)
#     return (non_text / len(b)) > 0.30


# def safe_base64_decode_if_text(s: str):
#     """
#     If s looks like base64 and decodes to readable text, return (decoded_text, True).
#     Otherwise return (original, False).
#     """
#     s_clean = s.strip()
#     if len(s_clean) < 16:
#         return s, False
#     if re.fullmatch(r"[A-Za-z0-9+/_=\s-]+", s_clean) is None:
#         return s, False

#     candidate = re.sub(r"\s+", "", s_clean)
#     try:
#         decoded = base64.b64decode(candidate, validate=True)
#     except Exception:
#         try:
#             decoded = base64.urlsafe_b64decode(candidate)
#         except Exception:
#             return s, False

#     try:
#         if looks_binary(decoded):
#             return s, False
#         text = decoded.decode("utf-8", errors="replace")
#         printable_ratio = sum(1 for ch in text if ch.isprintable()) / max(1, len(text))
#         if printable_ratio > 0.7:
#             return text, True
#         return s, False
#     except Exception:
#         return s, False


# def redact_value(value: str) -> str:
#     if not value:
#         return value
#     v = re.sub(r"([A-Fa-f0-9]{8,})([A-Fa-f0-9\-_.]{8,})?", "[REDACTED_TOKEN]", value)
#     v = re.sub(
#         r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "[REDACTED_JWT]", v
#     )
#     return v


# def redact_sensitive_headers(headers_text: str) -> str:
#     lines = []
#     for line in headers_text.splitlines():
#         if ":" not in line:
#             lines.append(line)
#             continue
#         k, v = line.split(":", 1)
#         k_lower = k.strip().lower()
#         if any(k_partial in k_lower for k_partial in SENSITIVE_KEYWORDS):
#             lines.append(f"{k}: [REDACTED]")
#             continue
#         redacted_val = redact_value(v.strip())
#         lines.append(f"{k}: {redacted_val}")
#     return "\n".join(lines)


# def normalize_query_string(query: str):
#     if not query:
#         return "", 0, ""
#     try:
#         params = urllib.parse.parse_qsl(query, keep_blank_values=True)
#     except Exception:
#         s = urllib.parse.unquote_plus(query)
#         return s, 0, ""

#     lines = []
#     for k, v in params:
#         k_norm = k.strip().lower()
#         v_decoded = urllib.parse.unquote_plus(v)
#         v_redacted = (
#             "[REDACTED]" if any(kpart in k_norm for kpart in SENSITIVE_KEYWORDS)
#             else redact_value(v_decoded)
#         )
#         lines.append(f"{k_norm}={v_redacted}")
#     return "\n".join(lines), len(params), ",".join([k for k, _ in params][:5])


# def normalize_path(path: str):
#     if not path:
#         return ""
#     try:
#         p = urllib.parse.unquote(path)
#     except Exception:
#         p = path
#     p = html.unescape(p).strip()
#     p = re.sub(r"/{2,}", "/", p)

#     def truncate_segment(seg):
#         return seg[:16] + "...[" + str(len(seg)) + "]" if len(seg) > 64 else seg

#     return "/".join([truncate_segment(seg) for seg in p.split("/")]).lower()


# def normalize_body(body: str):
#     if not body:
#         return ""
#     b = body.strip()
#     try:
#         parsed = json.loads(b)
#         if isinstance(parsed, dict):
#             for k in list(parsed.keys()):
#                 if any(sk in k.lower() for sk in SENSITIVE_KEYWORDS):
#                     parsed[k] = "[REDACTED]"
#         return json.dumps(parsed, sort_keys=True)
#     except Exception:
#         pass

#     if "=" in b and "&" in b and "%" in b:
#         try:
#             qs, _, _ = normalize_query_string(b)
#             return qs
#         except Exception:
#             pass

#     decoded, ok = safe_base64_decode_if_text(b)
#     if ok:
#         return decoded

#     try:
#         s = urllib.parse.unquote_plus(b)
#     except Exception:
#         s = b
#     s = html.unescape(s)
#     return re.sub(r"\s+", " ", redact_value(s))


# # ===========================
# # Detection Runner
# # ===========================

# def run_detectors(text: str):
#     suspicious_tags = []
#     score = 0

#     # generic attack patterns
#     for name, pattern in SUSPICIOUS_PATTERNS.items():
#         if pattern.search(text):
#             suspicious_tags.append(name)
#             score += 1

#     # credential leaks
#     for name, pattern in CREDENTIAL_PATTERNS.items():
#         if pattern.search(text):
#             suspicious_tags.append(f"leak:{name}")
#             score += 2

#     return suspicious_tags, score

# def normalize_chunk_text(chunk_text: str, chunk_type: str = None) -> tuple[str, dict]:
#     """
#     Higher-level normalizer used by collectors:
#       - Calls preprocess_payload(chunk_text, chunk_type) to get normalized text
#       - Computes suspicion_score and matched tags
#       - Optionally annotates suspicious tokens in the normalized text
#     Returns:
#       (normalized_text, meta_dict)
#         meta_dict contains:
#           - suspicion_score: int
#           - suspicious_tags: list[str]
#           - suspicious: bool (score > 0)
#     """
#     # keep the original normalization
#     normalized = preprocess_payload(chunk_text, chunk_type)

#     # compute suspicion
#     score, tags = compute_suspicion_score(normalized)

#     # annotate text for easier inspection (keeps original content)
#     annotated = annotate_suspicious_tokens(normalized) if score > 0 else normalized

#     meta = {
#         "suspicion_score": int(score),
#         "suspicious": bool(score > 0),
#         "suspicious_tags": tags,
#         "chunk_type": chunk_type or "unknown"
#     }

#     return annotated, meta

# # ===========================
# # Main Preprocess Entrypoint
# # ===========================

# def preprocess_payload(text: str, chunk_type: str = None):
#     if text is None:
#         return ""

#     if chunk_type == "path":
#         norm = normalize_path(text)
#     elif chunk_type == "query":
#         norm, _, _ = normalize_query_string(text)
#     elif chunk_type == "headers":
#         norm = redact_sensitive_headers(text)
#     elif chunk_type == "body":
#         norm = normalize_body(text)
#     else:
#         try:
#             norm = urllib.parse.unquote_plus(text)
#         except Exception:
#             norm = text
#         norm = html.unescape(re.sub(r"\s+", " ", norm))

#     suspicious_tags, suspicion_score = run_detectors(norm)

#     return {
#         "normalized": norm,
#         "suspicious_tags": suspicious_tags,
#         "suspicion_score": suspicion_score,
#     }
