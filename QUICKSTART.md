# Quick Start Guide - SQL Injection Learning Path

Get started with learning SQL injection in just a few steps!

## 🚀 For Complete Beginners

### Week 1: Foundations
**Day 1-2: Understanding the Basics**
- Read [What is SQL Injection?](01-basics/what-is-sqli.md)
- Watch: [OWASP SQL Injection explanation](https://owasp.org)
- Set up a practice environment (DVWA)

**Day 3-4: Types of SQLi**
- Study [Types of SQL Injection](01-basics/types-of-sqli.md)
- Understand in-band vs blind vs out-of-band
- Try basic payloads: `' OR '1'='1`

**Day 5-7: Common Locations**
- Learn [Common Injection Locations](01-basics/common-locations.md)
- Identify vulnerable points in applications
- Practice finding SQLi in DVWA

### Week 2: Basic Exploitation
**Day 8-10: UNION Attacks**
- Master [UNION Attacks](02-exploitation/union-attacks.md)
- Practice column enumeration
- Extract data from databases

**Day 11-14: Database Enumeration**
- Learn to list tables and columns
- Extract database version
- Study [Database-Specific Syntax](05-cheat-sheets/database-specific-syntax.md)

### Week 3-4: Blind SQLi
**Day 15-21: Boolean-Based**
- Study [Boolean-Based Blind SQLi](03-blind-sqli/boolean-based.md)
- Write simple Python scripts to automate
- Practice patience (it's slow!)

**Day 22-28: Advanced Techniques**
- Learn time-based and error-based techniques
- Explore out-of-band methods
- Practice on PortSwigger labs

---

## 🎯 For Intermediate Learners

### Focus Areas

1. **Automation**
   - Learn SQLMap
   - Write custom Python scripts
   - Understand tool limitations

2. **Advanced Techniques**
   - Second-order SQL injection
   - NoSQL injection (if interested)
   - WAF bypass techniques

3. **Real-World Practice**
   - Bug bounty platforms (authorized only!)
   - CTF competitions
   - Capture the Flag events

---

## 🛠️ Setting Up Your Lab

### Option 1: Docker (Recommended)

```bash
# DVWA (Damn Vulnerable Web Application)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Access at: http://localhost
# Default credentials: admin / password
```

### Option 2: Virtual Machine

```bash
# Download OWASP Broken Web Apps VM
# Or Metasploitable 2
# Or create your own vulnerable app
```

### Option 3: Online Labs

- **PortSwigger Academy** (Free): https://portswigger.net/web-security/sql-injection
- **HackTheBox** (Freemium): https://www.hackthebox.eu/
- **TryHackMe** (Freemium): https://tryhackme.com/

---

## 📚 Recommended Learning Path

### Phase 1: Theory (1 week)
```
✓ Read all files in 01-basics/
✓ Understand different SQLi types
✓ Learn basic SQL if needed
```

### Phase 2: Practice (2-3 weeks)
```
✓ Set up vulnerable lab
✓ Practice UNION attacks
✓ Try manual exploitation
✓ Learn one automation tool
```

### Phase 3: Advanced (2-3 weeks)
```
✓ Master blind SQLi
✓ Write custom scripts
✓ Learn WAF bypass
✓ Study real-world examples
```

### Phase 4: Prevention (1 week)
```
✓ Study secure coding practices
✓ Learn parameterized queries
✓ Understand defense in depth
✓ Review code examples
```

---

## 🎓 Practice Checklist

### Basic Skills
- [ ] Identify SQL injection vulnerability
- [ ] Use `' OR '1'='1` successfully
- [ ] Determine number of columns
- [ ] Extract database version
- [ ] List all tables
- [ ] List columns in a table
- [ ] Extract user data

### Intermediate Skills
- [ ] Exploit blind SQL injection
- [ ] Write a basic Python exploit script
- [ ] Use SQLMap effectively
- [ ] Bypass basic filters
- [ ] Extract data via time delays
- [ ] Understand second-order SQLi

### Advanced Skills
- [ ] Bypass WAF protections
- [ ] Use out-of-band techniques
- [ ] Write advanced automation
- [ ] Chain SQLi with other vulns
- [ ] Perform code review for SQLi

---

## 🔧 Essential Tools

### Testing Tools
```bash
# SQLMap - Automated SQLi tool
sudo apt install sqlmap

# Burp Suite - Web proxy
# Download from: https://portswigger.net/burp

# OWASP ZAP - Free alternative to Burp
sudo apt install zaproxy
```

### Development Tools
```bash
# Python (for custom scripts)
sudo apt install python3 python3-pip

# Install useful libraries
pip3 install requests beautifulsoup4
```

---

## 📖 Study Resources

### Free Online Courses
1. **PortSwigger Web Security Academy**
   - Best free resource
   - Interactive labs
   - All SQLi types covered

2. **OWASP Testing Guide**
   - Comprehensive methodology
   - Real-world scenarios

3. **HackerOne Disclosed Reports**
   - Real bug bounty reports
   - Learn from actual findings

### Books (Optional)
- "The Web Application Hacker's Handbook"
- "SQL Injection Attacks and Defense"
- "The Tangled Web"

### Video Resources
- OWASP YouTube channel
- LiveOverflow (YouTube)
- IppSec (HackTheBox walkthroughs)

---

## ⚠️ Important Reminders

### Legal & Ethical
```
✅ DO:
- Practice on your own systems
- Use authorized testing platforms
- Follow responsible disclosure
- Respect bug bounty program rules

❌ DON'T:
- Test without permission
- Attack production systems
- Ignore responsible disclosure
- Keep vulnerabilities secret for profit
```

### Best Practices
```
✓ Always get written authorization
✓ Keep detailed notes
✓ Document your findings
✓ Learn defensive coding too
✓ Stay updated on new techniques
```

---

## 🎯 30-Day Challenge

### Week 1: Foundations
- [ ] Read all basic guides
- [ ] Set up DVWA
- [ ] Complete 5 PortSwigger labs
- [ ] Practice basic UNION attacks

### Week 2: Exploitation
- [ ] Master column enumeration
- [ ] Extract data from 3 different DBs
- [ ] Write your first Python script
- [ ] Learn SQLMap basics

### Week 3: Blind SQLi
- [ ] Complete boolean-based challenges
- [ ] Try time-based exploitation
- [ ] Automate one blind SQLi attack
- [ ] Study error-based techniques

### Week 4: Advanced & Defense
- [ ] Learn one bypass technique
- [ ] Study secure coding practices
- [ ] Review 5 real CVEs
- [ ] Write a report on a finding

---

## 💡 Pro Tips

### Efficiency Tips
1. **Use automation wisely** - Understand manual exploitation first
2. **Take notes** - Document every finding
3. **Practice daily** - Even 30 minutes helps
4. **Join communities** - Learn from others
5. **Stay curious** - Always ask "why?"

### Avoiding Burnout
- Don't rush through topics
- Take breaks when stuck
- Celebrate small wins
- Mix theory with practice
- Find a study buddy

---

## 📝 Progress Tracking

Create a simple log:

```markdown
# My SQLi Learning Log

## Date: 2025-02-12
**Topic**: UNION Attacks
**Completed**: 
- Read union-attacks.md
- Practiced on DVWA
- Completed 2 PortSwigger labs

**Challenges**:
- Column enumeration was confusing at first

**Next Steps**:
- Practice more with different column counts
- Try extracting real data
```

---

## 🤝 Getting Help

### When You're Stuck
1. Re-read the relevant guide
2. Check the cheat sheet
3. Google the error message
4. Ask in communities:
   - Reddit: r/websecurity, r/netsec
   - Discord: Various security servers
   - Stack Overflow: For technical questions

### Asking Good Questions
```
❌ "SQLi doesn't work, help!"

✅ "I'm trying UNION SQLi on DVWA (MySQL). I determined 
   there are 2 columns but getting error 'different number 
   of columns'. My payload: ' UNION SELECT NULL,NULL--
   What am I missing?"
```

---

## 🎊 Completion Checklist

You've mastered SQL injection when you can:
- [ ] Explain different SQLi types
- [ ] Identify vulnerable code
- [ ] Manually exploit in-band SQLi
- [ ] Extract data via blind SQLi
- [ ] Use automation tools effectively
- [ ] Write secure code to prevent SQLi
- [ ] Understand database-specific syntax
- [ ] Chain SQLi with other attacks
- [ ] Write clear vulnerability reports

---

**Ready to begin? Start with [What is SQL Injection?](01-basics/what-is-sqli.md)**

**Good luck on your learning journey! 🚀**
