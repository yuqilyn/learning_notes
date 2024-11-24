## 什么是JWT?
`JSON Web 令牌 (JWT) 是一种在系统之间发送加密签名 JSON 数据的标准化格式。理论上，它们可以包含任何类型的数据，但最常用于在身份验证、会话处理和访问控制机制中发送有关用户的信息（“声明”）。`<br /> 
`由于此信息经过了数字签名，因此可以验证和信任。JWT 可以使用密钥（使用 HMAC 算法）或使用 RSA 或 ECDSA 的公钥/私钥对进行签名。`<br />
`与传统会话令牌不同，服务器所需的所有数据都存储在客户端的 JWT 本身中。这使得 JWT 成为高度分布式网站的热门选择，因为用户需要与多个后端服务器无缝交互。`
### JWT的格式
##### #example(三部分之间用.隔开)
```
#header:
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.
#payload:
eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.
#signature:
SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```
##### 第一部分:header
`标头通常由两部分组成：令牌的类型（即 JWT）和正在使用的签名算法（例如 HMAC SHA256 或 RSA）。`<br />
`**这个json数据是由Base64Url加密而来**`<br />
#example:
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```
##### 第二部分:payload
`令牌的第二部分是有效负载，其中包含声明。声明是关于实体（通常是用户）和其他数据的声明。`<br />
`**这个json数据是由Base64Url加密而来**`<br />
`声明有三种类型：注册声明、公共声明和私有声明。`<br />
###### 1、注册声明
```
这是一组预定义的声明，它们不是强制性的，但建议使用，以提供一组有用的、
可互操作的声明。其中一些是：iss（颁发者）、exp（到期时间）、sub（主题）、aud（受众）等。
```
###### 2、公共声明
```
这些可以由使用 JWT 的人随意定义。
但为了避免冲突，它们应该在 IANA JSON Web Token Registry 中定义，或定义为包含抗冲突命名空间的 URI。
```
###### 3、私有声明
```
这些是为了在同意使用它们的各方之间共享信息而创建的自定义声明，既不是注册声明也不是公开声明。
```
#example:
```
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
##### 第三部分:signature
`签名用于验证消息在传输过程中未被更改，并且，对于使用私钥签名的令牌，它还可以验证 JWT 的发送者是否是其所述的那个人。`<br />
`要创建签名部分，您必须获取编码的标头、编码的有效负载、密钥、标头中指定的算法，然后对其进行签名。`

#example( HMAC SHA256):
```
HMACSHA256(
   base64UrlEncode( header ) +"."+
   base64UrlEncode( payload ),
   secret )
```
##### 下图展示了如何获取 JWT 以及如何使用它来访问 API 或资源：
![image](https://github.com/user-attachments/assets/9bf9e9f3-2896-4e04-a22b-ef9d98251987)
```
1、应用程序或客户端向授权服务器请求授权。这是通过不同的授权流程之一执行的。
   例如，典型的符合 OpenID Connect 的 Web 应用程序将使用授权代码流程通过 /oauth/authorize 端点。
2、当授权被批准时，授权服务器会向应用程序返回访问令牌（JWT）。
3、应用程序使用访问令牌来访问受保护的资源（如 API）。
```
### JWT相比于SWT(Simple Web Tokens)和SAML(Security Assertion Markup Language Tokens)两种令牌的优势
`1、JWT更轻量级更紧凑；`<br />
    `由于 JSON 比 XML 更简洁，因此编码后的大小也更小，使得 JWT 比 SAML 更紧凑。这使得 JWT 成为在 HTML 和 HTTP 环境中传递的理想选择。`<br />
`2、安全方面 `<br />
   `SWT 只能使用 HMAC 算法通过共享密钥进行对称签名。但是，JWT 和 SAML 令牌可以使用 X.509 证书形式的公钥/私钥对进行签名。`<br />
   `与签署 JSON 的简单性相比，使用 XML 数字签名对 XML 进行签署而不引入隐蔽的安全漏洞非常困难。`<br />
`3、JSON解析器在各种编程语言很常见，相反，XML 没有自然的文档到对象映射。这使得使用 JWT 比使用 SAML 断言更容易。`<br />
`4、就使用而言，JWT 在互联网规模上使用。这凸显了 JSON Web 令牌在多个平台（尤其是移动平台）上的客户端处理的简易性。`<br />


