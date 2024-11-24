### **[一. Injection](#Injection-text)**  
### **[二. Broken Authentication](#Authentication)**  
### **[三. Sensitive Data Exposure](#Sensitive-Data-Exposure)**  
### **[四. XML External Entity](#XML-External-Entity)**  
### **[五. Broken Access Control](#Broken-Access-Control)**  
### **[六. Security Misconfiguration](#Security-Misconfiguration)**  
### **[七. Cross-site Scripting](#Cross-site-Scripting)**  
### **[八. Insecure Deserialization](#Insecure-Deserialization)**  
### **[九. Components with Known Vulnerabilities](#Components-with-Known-Vulnerabilities)**  
### **[十. Insufficient Logging & Monitoring](#Insufficient-Logging-Monitoring)**  

<a name="Injection-text"></a>
# **Injection**
## 发生的原因
   `用户控制的输入被应用程序解释为实际命令或参数。
   注入攻击取决于所使用的技术以及这些技术如何精确地解释输入。`
## 攻击的类型
  #### 1、SQL Injection
  ##### 原因 
  `当用户控制的输入被传递给 SQL 查询时，就会发生这种情况。因此,攻击者可以传入 SQL 查询来操纵此类查询的结果。`
  ##### 造成的危害
 `当此输入传递到数据库查询中时，访问、修改和删除数据库中的信息。这意味着攻击者可以窃取敏感信息，例如个人信息和凭证。`
  #### 2、Command injection
  ##### 原因 
  `当用户输入传递到系统命令时，当 Web 应用程序中的服务器端代码（如 PHP）在托管计算机上进行系统调用时，就会发生命令注入。从而攻击者能够在应用服务器上执行任意系统命令。`
  ##### 造成的危害
  `在服务器上执行任意系统命令，允许攻击者访问用户的系统。这将使他们能够窃取敏感数据并对执行命令的服务器所链接的基础设施进行更多攻击。`<br />
  `生成一个反向 shell，成为运行 Web 服务器的用户。只需一个简单的 ;nc -e /bin/bash，他们就拥有了你的服务器；`
  
## 如何预防
防止注入攻击的主要措施是确保用户控制的输入不会被解释为查询或命令。有多种方法可以做到这一点：<br />
   `1.使用允许列表(白名单)：当输入发送到服务器时，将此输入与安全输入或字符列表进行比较。如果输入被标记为安全，则处理该输入。否则，该输入将被拒绝，并且应用程序会抛出错误。`<br />
   `2.剥离输入(过滤转义)：如果输入包含危险字符，则在处理之前删除这些字符。`
<a name="Authentication"></a>
# ****
<a name="Sensitive-Data-Exposure"></a>
<a name="XML-External-Entity"></a>
<a name="Broken-Access-Control"></a>
<a name="Security-Misconfiguration"></a>
<a name="Cross-site-Scripting"></a>
<a name="Insecure-Deserialization"></a>
<a name="Components-with-Known-Vulnerabilities"></a>
<a name="Insufficient-Logging-Monitoring"></a>
