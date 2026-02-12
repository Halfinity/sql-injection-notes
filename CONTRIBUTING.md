# Contributing to SQL Injection Notes

First off, thank you for considering contributing to this project! 🎉

## How Can I Contribute?

### Reporting Issues

- **Check existing issues** first to avoid duplicates
- Use the issue tracker to report bugs or suggest features
- Provide clear descriptions with examples
- Include steps to reproduce (if applicable)

### Suggesting Enhancements

- **New techniques**: Share new SQLi techniques or variations
- **Better examples**: Provide clearer or more practical examples
- **Additional databases**: Coverage for other database systems
- **Tools and resources**: Suggest useful tools or learning resources

### Pull Requests

1. **Fork the repository**
2. **Create a branch** for your changes
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our guidelines
4. **Test your changes** for accuracy
5. **Commit with clear messages**
   ```bash
   git commit -m "Add: Description of what you added"
   git commit -m "Fix: Description of what you fixed"
   git commit -m "Update: Description of what you updated"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request** with a clear description

## Content Guidelines

### Writing Style

- **Clear and concise**: Explain concepts simply
- **Practical examples**: Include real-world scenarios
- **Code formatting**: Use proper markdown code blocks
- **Accurate information**: Double-check all technical details
- **Attribution**: Credit sources when applicable

### File Organization

```
sql-injection-notes/
├── 01-basics/          # Fundamental concepts
├── 02-exploitation/    # Attack techniques
├── 03-blind-sqli/      # Blind injection methods
├── 04-advanced/        # Advanced topics
├── 05-cheat-sheets/    # Quick references
└── 06-prevention/      # Security measures
```

### Markdown Format

- Use proper heading hierarchy (# → ## → ###)
- Include code syntax highlighting
  ```sql
  SELECT * FROM users WHERE id = 1
  ```
- Use tables for comparisons
- Add horizontal rules (---) between major sections
- Include emoji sparingly for visual breaks 🎯

### Code Examples

#### Good Example ✅

```sql
-- Vulnerable query
SELECT * FROM products WHERE category = 'USER_INPUT'

-- Attack payload
' UNION SELECT username, password FROM users--

-- Resulting query
SELECT * FROM products WHERE category = '' UNION SELECT username, password FROM users--'
```

#### Include Context

```sql
-- Context: E-commerce product filtering
-- Vulnerability: Unfiltered user input in WHERE clause
-- Impact: Data disclosure

-- Original query
SELECT name, price FROM products WHERE category = '$_GET[cat]'

-- Attack
?cat=' UNION SELECT username, password FROM admin_users--

-- Result: Admin credentials exposed in product listing
```

### Safety and Ethics

**All contributions must:**
- Include ethical usage disclaimers
- Emphasize legal and authorized testing only
- Provide defensive coding examples
- Promote responsible disclosure

**Never include:**
- Actual credentials or sensitive data
- Instructions targeting specific real-world systems
- Exploits without defensive measures
- Content encouraging illegal activity

## Technical Accuracy

### Testing Your Examples

Before submitting:
1. Verify syntax for each database type
2. Test examples in a local environment (if applicable)
3. Ensure all SQL queries are properly formatted
4. Check that exploitation techniques are current

### Database Coverage

When adding database-specific content:
- Include all major databases where applicable:
  - MySQL
  - PostgreSQL
  - Microsoft SQL Server
  - Oracle
- Note any database-specific limitations
- Provide syntax variations

## Documentation Standards

### New Techniques

When documenting a new technique:

1. **Explanation**: What is it?
2. **How it works**: Technical details
3. **Use cases**: When to use it
4. **Examples**: Practical demonstrations
5. **Prevention**: How to defend against it

### Example Template

```markdown
# [Technique Name]

## Overview
Brief description of the technique

## How It Works
Technical explanation with diagrams if helpful

## Example Scenario
Real-world context

### Step-by-Step
1. Step one with code
2. Step two with code
3. Step three with code

## Database-Specific Notes
- MySQL: specific notes
- PostgreSQL: specific notes
- MSSQL: specific notes
- Oracle: specific notes

## Prevention
How to defend against this technique

## Key Takeaways
- Bullet point 1
- Bullet point 2

## References
- [Source 1](url)
- [Source 2](url)
```

## Review Process

### What We Look For

- ✅ Technical accuracy
- ✅ Clear explanations
- ✅ Practical examples
- ✅ Proper formatting
- ✅ Ethical framing
- ✅ No spelling/grammar errors

### Feedback

- We'll review your PR as soon as possible
- We may request changes or clarifications
- Don't take feedback personally - we all learn together!

## Resources for Contributors

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity)

### Testing Environments
- [DVWA](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [bWAPP](http://www.itsecgames.com/)

### Tools
- [SQLMap](http://sqlmap.org/)
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of background or experience level.

### Expected Behavior

- Be respectful and constructive
- Accept feedback gracefully
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discriminatory language
- Promoting illegal activities
- Sharing private information
- Trolling or inflammatory comments

## Questions?

Feel free to:
- Open an issue for discussion
- Reach out to maintainers
- Start a discussion in the community

---

**Thank you for contributing to making the internet more secure! 🔒**
