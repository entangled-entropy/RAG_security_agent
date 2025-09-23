# ATTACK Markers Fix Summary

## Problem Description

The normalization system was causing false positives in version detection due to improper handling of `[ATTACK:` markers in traffic data. The specific issue was:

1. **ATTACK markers in input data**: Traffic contained markers like `[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]`
2. **False positives**: These markers were being treated as version strings, causing incorrect version detection
3. **Unreadable output**: The normalized text contained nested ATTACK markers making it unreadable
4. **Version detection failure**: Real version numbers were being masked by aggressive JWT redaction

## Root Cause Analysis

1. **Input processing**: The normalization function was processing ATTACK markers as part of the content instead of cleaning them first
2. **Return value**: The function was returning the annotated version (with ATTACK markers) instead of clean normalized text
3. **JWT redaction**: The JWT redaction pattern was too aggressive, matching simple version numbers like `8.1.2`

## Solution Implemented

### 1. Added `clean_attack_markers()` Function

```python
def clean_attack_markers(text: str) -> str:
    """
    Clean ATTACK markers from input text to restore original content.
    This removes [ATTACK:...] markers that were added during annotation.
    """
    if not text:
        return text
    
    # Remove ATTACK markers while preserving the original content
    # Pattern: [ATTACK:content] -> content
    cleaned = re.sub(r'\[ATTACK:([^\]]*)\]', r'\1', text)
    
    # Handle nested ATTACK markers by applying the pattern multiple times
    # This handles cases like [ATTACK:[ATTACK:content]] -> content
    prev_cleaned = ""
    while cleaned != prev_cleaned:
        prev_cleaned = cleaned
        cleaned = re.sub(r'\[ATTACK:([^\]]*)\]', r'\1', cleaned)
    
    return cleaned
```

### 2. Modified `normalize_chunk_text()` Function

- **Input cleaning**: Added `cleaned_input = clean_attack_markers(chunk_text)` before processing
- **Return value**: Changed from returning `annotated` to returning `normalized` (clean text)
- **Metadata preservation**: Added `annotated_text` to metadata for forensic analysis
- **Stack detection**: Updated to use `cleaned_input` instead of original `chunk_text`

### 3. Fixed JWT Redaction Pattern

**Before:**
```python
v = re.sub(r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "[REDACTED_JWT]", v)
```

**After:**
```python
# JWT pattern: at least 10 chars per part, not just version numbers like 8.1.2
v = re.sub(r"[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}", "[REDACTED_JWT]", v)
```

## Test Results

### Before Fix
```
❌ FAIL: Normalized text still contains ATTACK markers
❌ False positive: [ATTACK:(]X11 found in normalized text
❌ Missing: PHP/8.1.2
❌ Missing: nginx/1.20.2
❌ Missing: Laravel/9.0.0
```

### After Fix
```
✅ SUCCESS: Normalized text is clean (no ATTACK markers)
✅ SUCCESS: ATTACK markers preserved in metadata for forensic analysis
✅ Found: Firefox/142.0
✅ Found: PHP/8.1.2
✅ Found: nginx/1.20.2
✅ Found: Laravel/9.0.0
✅ No false positive: [ATTACK:(]X11 not in normalized text
```

## Example Transformation

### Input (with ATTACK markers)
```
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
```

### Output (clean normalized text)
```
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/[REDACTED_TOKEN] Firefox/142.0
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
```

### Metadata (for forensic analysis)
```
annotated_text: "User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/[REDACTED_TOKEN] Firefox/142.0"
```

## Benefits

1. **Clean output**: Normalized text is now readable and free of ATTACK markers
2. **Accurate version detection**: Real version numbers are properly detected
3. **No false positives**: ATTACK markers no longer cause false version detection
4. **Forensic preservation**: Original ATTACK markers are preserved in metadata for analysis
5. **Backward compatibility**: Existing functionality is preserved while fixing the issues

## Files Modified

1. `src/zap_rag_security_agent/preprocessing/normalizer.py`
   - Added `clean_attack_markers()` function
   - Modified `normalize_chunk_text()` function
   - Fixed JWT redaction pattern in `redact_value()` function

2. `tests/` directory
   - Created comprehensive test cases for ATTACK marker handling
   - Added standalone test to verify the fix

## Testing

The fix has been thoroughly tested with:
- Real problematic traffic samples from the user's issue
- Various ATTACK marker patterns
- Version detection accuracy
- Suspicion score calculation
- Edge cases and malformed markers

All tests pass successfully, confirming that the fix resolves the false positive issues while maintaining forensic analysis capabilities.
