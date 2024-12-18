## JWT Attack
### 什么是JWT攻击?
`JWT 攻击涉及用户向服务器发送修改后的 JWT，以实现恶意目标。通常，此目标是通过冒充已通过身份验证的另一个用户来绕过身份验证和访问控制。`
### JWT漏洞产生的原因
`JWT 漏洞通常是由于应用程序本身的 JWT 处理存在缺陷而引起的:`</br>
`  1、JWT 相关的各种规范在设计上相对灵活，允许网站开发人员自己决定许多实现细节。这就导致有些开发人员在设计的时候对JWT的签名没有做到正确的验证,这使得攻击者能够篡改通过令牌的有效负载传递给应用程序的值。`</br>
`  2、即使签名经过了严格的验证，它是否真正值得信任在很大程度上取决于服务器的密钥是否保密。如果该密钥以某种方式泄露，或者被猜测或暴力破解，攻击者可以为任意令牌生成有效签名，从而危及整个机制。`</br>
### JWT攻击造成的影响
`如果攻击者能够创建具有任意值的有效令牌，他们就可能提升自己的权限或冒充其他用户，从而完全控制他们的帐户。`
### 如何防止JWT攻击
`1、使用最新的库来处理 JWT，并确保您的开发人员完全了解其工作原理以及任何安全隐患，现代库使您更难以无意中以不安全的方式实现它们，但由于相关规范固有的灵活性，这并非万无一失。`</br>
`2、确保对收到的任何 JWT 执行正确有效的签名验证，并考虑使用意外算法签名的 JWT 等边缘情况。`<br/>
`3、针对 jku 标头强制执行允许主机的严格白名单`</br>
`4、确保您不会通过 kid 标头参数受到路径遍历或 SQL 注入的攻击。`</br>
`5、为发行的任何令牌设置到期日期。`</br>
`6、尽可能避免在 URL 参数中发送令牌。`</br>
`7、使发行服务器能够撤销令牌（例如，在注销时）。`</br>

### 常见的JWT攻击方式(参考BP官网靶场)
#### 一、利用有缺陷的 JWT 签名验证（及未验证签名或验证不严格）
##### 漏洞产生原因
`根据设计，服务器通常不会存储有关其发出的 JWT 的任何信息。相反，每个令牌都是一个完全独立的实体。`<br/>
`这样做带来了一个根本问题——服务器实际上并不知道令牌的原始内容，甚至不知道原始签名是什么。`<br/>
`因此，如果服务器不能正确验证签名，就无法阻止攻击者对令牌的其余部分进行任意更改。`<br/>
##### （1）接受任意签名
```
JWT 库通常提供一种验证令牌的方法和另一种仅解码令牌的方法。例如，Node.js 库 jsonwebtoken 具有 verify() 和 decrypt()。
有时，开发人员会混淆这两种方法，只将传入的令牌传递给decode()方法。
这实际上意味着应用程序根本不验证签名。即接受任意签名，这就导致攻击者可以修改任意身份进行登录和越权操作
```
##### (2)接受无签名的token
`除其他内容外，JWT 标头还包含一个 alg 参数。这会告诉服务器使用哪种算法对令牌进行签名，以及在验证签名时需要使用哪种算法。`
```
{
    "alg": "HS256",
    "typ": "JWT"
}
```
`这本质上是有缺陷的，因为服务器别无选择，只能隐式地信任来自令牌的用户可控制的输入，而此时令牌根本没有经过验证。`<br/>
`换句话说，攻击者可以直接影响服务器检查令牌是否可信的方式。`<br/>
`JWT 可以使用多种不同的算法进行签名，但也可以不签名。在这种情况下，alg 参数设置为 none，表示所谓的“不安全的 JWT”。`<br/>
`由于这种做法的明显危险，服务器通常会拒绝没有签名的令牌。`<br/>
`但是，由于这种过滤依赖于字符串解析，因此有时您可以使用经典的混淆技术（例如混合大写和意外编码）来绕过这些过滤器。例如None,NoNe,none...`<br/>

#### 二、暴力破解密钥
##### 漏洞产生原因
`一些签名算法（例如 HS256 (HMAC + SHA-256)）使用任意独立字符串作为密钥。就像密码一样，这个密钥不能被攻击者轻易猜出或暴力破解，
这一点至关重要。否则，他们可能能够使用他们喜欢的任何标头和有效负载值创建 JWT，然后使用该密钥使用有效签名重新签署令牌。`<br/>
`在实施 JWT 应用程序时，开发人员有时会犯一些错误，例如忘记更改默认或占位符密钥。他们甚至可能复制和粘贴他们在网上找到的代码片段
，然后忘记更改作为示例提供的硬编码密钥。在这种情况下，攻击者使用众所周知的密钥单词表暴力破解服务器的密钥可能轻而易举。`
##### 推荐使用hashcat进行爆破
```
hashcat -a 0 -m 16500 jwt /usr/share/wordlists/jwt_secret
```
`Hashcat 使用单词表中的每个秘密对 JWT 中的标头和有效负载进行签名，然后将生成的签名与来自服务器的原始签名进行比较`<br/>
`如果任何签名匹配，hashcat 将以以下格式输出已识别的秘密以及其他各种详细信息：`</br>
```
<jwt>:<identified-secret>
```
#####然后使用burp的Json Web Tokens插件，修改完你要修改的信息后，输入密钥后重新计算签名
![image](https://github.com/user-attachments/assets/0a88f532-527a-49e8-aaa4-69e784b5d01a)
#### 三、JWT 标头参数注入
##### JWT标头易受攻击参数简介
`根据 JWS 规范，只有 alg 标头参数是强制性的。但实际上，JWT 标头（也称为 JOSE 标头）通常包含其他几个参数。以下参数对攻击者特别感兴趣。`<br/>
```
1、jwk (JSON Web Key) -- 提供代表密钥的嵌入式 JSON 对象
2、jku (JSON Web Key Set URL) -- 提供一个 URL，服务器可以从中获取一组包含正确密钥的密钥组。
3、kid (Key ID) -- 提供一个 ID，当有多个密钥可供选择时，服务器可以使用它来识别正确的密钥。根据密钥的格式，它可能具有匹配的 kid 参数。
```
`如您所见，这些用户可控制的参数分别告诉接收方服务器在验证签名时使用哪个密钥。这为实现给服务器指定自己的密钥提供了可能性`
##### （1）通过 jwk 参数注入自签名 JWT
`JSON Web 签名 (JWS) 规范描述了一个可选的 jwk 标头参数，服务器可以使用它来将其公钥以 JWK 格式直接嵌入到令牌本身中。`<br/>
#example header:
```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```
###### 漏洞产生原因
```
理想情况下，服务器应仅使用有限的公钥白名单来验证 JWT 签名。但是，配置错误的服务器有时会使用嵌入在 jwk 参数中的任何密钥。
您可以使用自己的 RSA 私钥对修改后的 JWT 进行签名，然后将匹配的公钥嵌入 jwk 标头中，从而利用此漏洞。
```
###### 使用BP的插件JWT Editer来测试该类型漏洞
```
1、加载扩展后，在 Burp 的主选项卡栏中，转到 JWT 编辑器密钥选项卡。
2、生成新的 RSA 密钥。
3、向 Burp Repeater 发送包含 JWT 的请求。
4、在消息编辑器中，切换到扩展生成的 JSON Web Token 选项卡，并根据需要修改令牌的有效负载。
5、单击攻击，然后选择嵌入式 JWK。出现提示时，选择新生成的 RSA 密钥。
6、发送请求以测试服务器的响应方式。
```
![image](https://github.com/user-attachments/assets/50ccc8f5-bb05-41ab-86ad-c0fb10339691)

![image](https://github.com/user-attachments/assets/c6b9c225-883d-4b4f-90f4-32e2c5146971)

![image](https://github.com/user-attachments/assets/d9dbe216-34d8-4e1c-9454-5148d0d07f55)

##### （2）通过 jku 参数注入自签名 JWT
`一些服务器不直接使用 jwk 标头参数嵌入公钥，而是允许您使用 jku（JWK Set URL）标头参数来引用包含密钥的 JWK Set。验证签名时，服务器会从此 URL 获取相关密钥。`<br/>
###### JWK Set介绍
`JWK Set 是一个 JSON 对象，其中包含代表不同键的 JWK 数组。`<br/>
#example:
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```
`更安全的网站只会从受信任的域获取密钥，但有时您可以利用 URL 解析差异来绕过这种过滤。`<br/>
#绕过方式:
###### 1、您可以使用 @ 字符将凭据嵌入到主机名前的 URL 中。例如：
`https://expected-host:fakepassword@evil-host`<br/>
###### 2、您可以使用 # 字符来表示 URL 片段。例如：
`https://evil-host#expected-host`<br/>
###### 3、您可以利用 DNS 命名层次结构将所需的输入放入您控制的完全限定 DNS 名称中。例如：
`https://expected-host.evil-host`<br/>
###### 4、您可以对字符进行 URL 编码，以混淆 URL 解析代码。如果实现过滤器的代码处理 URL 编码字符的方式与执行后端 HTTP 请求的代码不同，则这种方法特别有用。您还可以尝试对字符进行双重编码；某些服务器会递归地对收到的输入进行 URL 解码，这可能会导致进一步的差异
![image](https://github.com/user-attachments/assets/82a7de7d-8506-4cf4-b1d7-bfd0fc92fc2a)
##### （3）通过 kid 参数注入自签名 JWT
`服务器可能会使用多个加密密钥来签署不同类型的数据，而不仅仅是 JWT。因此，JWT 的标头可能包含 kid（密钥 ID）参数，这有助于服务器识别在验证签名时要使用的密钥。`<br/>
`验证密钥通常存储为 JWK 集。在这种情况下，服务器可能只是查找与令牌具有相同 kid 的 JWK。但是，JWS 规范并未为此 ID 定义具体的结构 - 它只是开发人员选择的任意字符串。例如，他们可能使用 kid 参数指向数据库中的特定条目，甚至是文件的名称。`<br/>
`如果此参数也容易受到目录遍历的攻击，攻击者可能会强制服务器使用其文件系统中的任意文件作为验证密钥。`<br/>
`如果服务器还支持使用对称算法签名的 JWT，则这种情况尤其危险。在这种情况下，攻击者可能会将 kid 参数指向可预测的静态文件，然后使用与此文件内容匹配的密钥对 JWT 进行签名。`<br/>
**`理论上，您可以对任何文件执行此操作，但最简单的方法之一是使用 /dev/null，它存在于大多数 Linux 系统上。由于这是一个空文件，因此读取它会返回一个空字符串。因此，使用空字符串对令牌进行签名将产生有效的签名。`**
```
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```
`如果服务器将其验证密钥存储在数据库中，则 kid 标头参数也是 SQL 注入攻击的潜在载体。`
![image](https://github.com/user-attachments/assets/e99997cb-1cff-4c1f-a55c-67503e69f7b5)
##### （4）一些其他的可被攻击的标头参数
```
cty（内容类型） - 有时用于声明 JWT 有效负载中内容的媒体类型。这通常会从标头中省略，但底层解析库可能无论如何都会支持它。如果您找到了绕过签名验证的方法，可以尝试注入 cty 标头以将内容类型更改为 text/xml 或 application/x-java-serialized-object，这可能会为 XXE 和反序列化攻击提供新的载体。

x5c（X.509 证书链） - 有时用于传递用于对 JWT 进行数字签名的密钥的 X.509 公钥证书或证书链。此标头参数可用于注入自签名证书，类似于上面讨论的 jwk 标头注入攻击。由于 X.509 格式及其扩展的复杂性，解析这些证书也可能引入漏洞。这些攻击的详细信息超出了这些材料的范围，但有关更多详细信息，请查看 CVE-2017-2800 和 CVE-2018-2633。
```

#### 四、JWT 算法混乱
[对称加密算法和非对称加密算法介绍](#symmetric)

`介绍:`<br/>
```
即使服务器使用了您无法暴力破解的强密码，您仍然可以通过使用开发人员未曾预料到的算法对令牌进行签名来伪造有效的 JWT。这被称为算法混淆攻击。
算法混淆攻击（也称为密钥混淆攻击）是指攻击者能够强制服务器使用与网站开发人员预期不同的算法来验证 JSON Web 令牌 (JWT) 的签名。
如果这种情况处理不当，攻击者可能会伪造包含任意值的有效 JWT，而无需知道服务器的秘密签名密钥。
```
##### 产生原因
```
算法混淆漏洞通常是由于 JWT 库的实现存在缺陷而引起的。尽管实际验证过程因所用算法而异，但许多库都提供了一种与算法无关的签名验证方法。
这些方法依赖于令牌标头中的 alg 参数来确定它们应执行的验证类型。
```
#example:
```
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```
`当网站开发人员随后使用此方法时，他们会假设该方法将专门处理使用 RS256 等非对称算法签名的 JWT，这时就会出现问题。由于这个错误的假设，他们可能总是将一个固定的公钥(存储在服务器上)传递给该方法`<br/>
```
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```
`在这种情况下，如果服务器收到使用对称算法（如 HS256）签名的令牌，则库的通用 verify() 方法会将公钥视为 HMAC 密钥。这意味着攻击者可以使用 HS256 和公钥对令牌进行签名，服务器将使用相同的公钥来验证签名。`<br/>
##### 一般攻击步骤
###### 1、获取服务器的公钥(因为服务器进行验证的时候用的是自己本地的公钥作为HMAC密钥)
![image](https://github.com/user-attachments/assets/60cc16fc-043d-41b4-b074-da3ca6cd4326)
###### 2、将公钥转化为合适的格式
![image](https://github.com/user-attachments/assets/2a264d48-4dfe-4020-b00c-7d83a54c5a96)
![image](https://github.com/user-attachments/assets/7799c59d-0050-4c99-a29c-7a3b0c03e285)
###### 3、使用修改后的payload和设置alg为HS256的header构造恶意的JWT
![image](https://github.com/user-attachments/assets/9ee4251a-587b-4b47-b5ac-6a061fb99fb8)
###### 4、使用HS256进行签名，并使用公钥作为密钥
![image](https://github.com/user-attachments/assets/4ef53e96-6cf6-4075-bed5-5cad1cd99833)

##### 进阶————从现有的token令牌中派生公钥
`如果公钥不易获得，您仍然可以通过从一对现有 JWT 中派生密钥来测试算法混淆。使用 jwt_forgery.py 等工具，此过程相对简单。您可以在 rsa_sign2n GitHub 存储库中找到此脚本以及其他几个有用的脚本。`<br/>
[代码链接](https://github.com/silentsignal/rsa_sign2n)
`使用:`
```
python jwt_forgery.py <token1> <token2>
或者用bp官网准备的docker镜像（可能要将docker源换为官方源）
docker run --rm -it portswigger/sig2n <token1> <token2>
```
`然后使用生成的两个JWT和两个公钥进行尝试`









###### 两种不同方式的加密算法介绍
<a name="symmetric"></a><br/>
`JWT 可以使用多种不同的算法进行签名。其中一些算法（如 HS256 (HMAC + SHA-256)）使用“对称”密钥。这意味着服务器使用单个密钥来签名和验证令牌。显然，这需要保密，就像密码一样。`
![image](https://github.com/user-attachments/assets/e830bf41-f330-49f2-9761-862bb55abae3)
`其他算法（例如 RS256（RSA + SHA-256））使用“非对称”密钥对。该密钥对由一个私钥（服务器使用该私钥对令牌进行签名）和一个数学相关的公钥（可用于验证签名）组成。`
![image](https://github.com/user-attachments/assets/697962a7-ef6e-48ae-b161-a923ca15cf74)






