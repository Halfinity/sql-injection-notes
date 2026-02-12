# SQL Injection - Penetration Testing Notes

![SQL Injection Banner](https://img.shields.io/badge/Security-SQL%20Injection-red)
![Status](https://img.shields.io/badge/Status-Active-green)
![Level](https://img.shields.io/badge/Level-Junior%20to%20Advanced-blue)

A comprehensive guide to SQL Injection vulnerabilities for penetration testing and security research.

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Repository Structure](#repository-structure)
3. [Topics Covered](#topics-covered)
4. [Quick Reference](#quick-reference)
5. [Learning Path](#learning-path)
6. [Contributing](#contributing)
7. [Disclaimer](#disclaimer)

## 🎯 Introduction

This repository contains detailed notes on SQL Injection vulnerabilities, techniques, and prevention methods. It's designed as a learning resource for junior penetration testers and security enthusiasts.

## 📁 Repository Structure

```
sql-injection-notes/
├── README.md
├── 01-basics/
│   ├── what-is-sqli.md
│   ├── types-of-sqli.md
│   └── common-locations.md
├── 02-exploitation/
│   ├── retrieving-hidden-data.md
│   ├── subverting-logic.md
│   ├── union-attacks.md
│   └── examining-database.md
├── 03-blind-sqli/
│   ├── boolean-based.md
│   ├── error-based.md
│   ├── time-based.md
│   └── oast-techniques.md
├── 04-advanced/
│   ├── second-order-sqli.md
│   └── different-contexts.md
├── 05-cheat-sheets/
│   └── database-specific-syntax.md
└── 06-prevention/
    └── how-to-prevent.md
```

## 📖 Topics Covered

- **Basics**: Understanding SQL injection fundamentals
- **Classic SQLi**: UNION attacks, data retrieval, database enumeration
- **Blind SQLi**: Boolean-based, error-based, time-based techniques
- **Advanced**: Second-order SQLi, out-of-band exploitation
- **Prevention**: Parameterized queries and security best practices
- **Cheat Sheets**: Database-specific syntax for Oracle, MySQL, PostgreSQL, MSSQL

## 🚀 Quick Reference

### Common SQL Injection Payloads

```sql
-- Authentication Bypass
' OR '1'='1'--
' OR 1=1--
admin'--

-- UNION Attack
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- Comment Indicators
-- (SQL comment)
# (MySQL comment)
/* */ (C-style comment)
```

### Database Version Detection

| Database | Query |
|----------|-------|
| MySQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| Oracle | `SELECT * FROM v$version` |
| MSSQL | `SELECT @@version` |

## 🛤️ Learning Path

### For Beginners:
1. Start with [What is SQL Injection](01-basics/what-is-sqli.md)
2. Learn about [Types of SQL Injection](01-basics/types-of-sqli.md)
3. Practice [Retrieving Hidden Data](02-exploitation/retrieving-hidden-data.md)

### For Intermediate:
1. Master [UNION Attacks](02-exploitation/union-attacks.md)
2. Study [Blind SQL Injection](03-blind-sqli/)
3. Learn [Database Enumeration](02-exploitation/examining-database.md)

### For Advanced:
1. Explore [Out-of-Band Techniques](03-blind-sqli/oast-techniques.md)
2. Study [Second-Order SQL Injection](04-advanced/second-order-sqli.md)
3. Review [Prevention Techniques](06-prevention/how-to-prevent.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Additional examples
- Corrections
- New techniques
- Better explanations

## ⚠️ Disclaimer

**IMPORTANT**: This repository is for educational purposes only. SQL Injection is illegal when performed without proper authorization. Only practice these techniques on:
- Your own systems
- Authorized penetration testing engagements
- Legal bug bounty programs
- Intentionally vulnerable applications (like DVWA, WebGoat)

**Never** use these techniques against systems you don't have explicit permission to test.

## 📚 Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity)

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Happy Learning! 🎓**

*Remember: With great power comes great responsibility.*
