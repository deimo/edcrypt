import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15


# 生成公钥和私钥
# 方法1：通过pycryptodome库自行创建
def create_rsa_key():
    """
    生成RSA加解密的公钥和私钥
    :return:
    """
    key = RSA.generate(1024)
    encrypt_key = key.export_key(pkcs=8)
    print('encrypted_key: ', encrypt_key)
    with open('my_private_rsa_key.pem', 'wb') as f:
        f.write(encrypt_key)

    with open('my_rsa_public.pem', 'wb') as f:
        f.write(key.publickey().export_key())


# 方法2： 通过openssl库，详情可见博文


def encrypt(content):
    """
    对数据明文进行加密
    :param content:  需要加密的数据内容
    :return: 返回加密后base64编码串
    """
    global pukb
    with open('./keys/public_key.pem') as pbf:
        pukb = pbf.read()

    pub_key = RSA.import_key(pukb)
    cipher = PKCS1_v1_5.new(pub_key)
    raw_encrypt_data = cipher.encrypt(content.encode('utf8'))
    encrypt_b64_data = base64.b64encode(raw_encrypt_data)

    return encrypt_b64_data.decode('utf8')


def decrypt(en_data):
    """
    解密加密后得到的数据
    :param en_data: 加密后经base64编码的串
    :return:  返回解密后并经过utf8解码的原始数据
    """
    global prikb
    with open('./keys/private_key.pem') as prf:
        prikb = prf.read()

    pri_key = RSA.import_key(prikb)
    cipher = PKCS1_v1_5.new(pri_key)

    en_b64_data = base64.b64decode(en_data.encode('utf8'))
    de_data = cipher.decrypt(en_b64_data, None)

    return de_data.decode('utf-8')


def rsa_sign(message):
    """
    对明文使用私钥加密
    :param message:  数据明文
    :return: 明文数据签名，和明文经加密被base64编码后得到的字符串
    """
    global prikb
    with open('./keys/private_key.pem') as prf:
        prikb = prf.read()
    pri_key = RSA.import_key(prikb)
    signer = pkcs1_15.new(pri_key)

    hash_obj = SHA1.new(message.encode('utf8'))
    raw_sign = signer.sign(hash_obj)    # 得到二进制签名
    sign = base64.b64encode(raw_sign)   # base64编码

    return sign.decode('utf8')          # utf8解码，可视


def rsa_signverify(message, sign):
    global pukb
    with open('./keys/public_key.pem') as pbf:
        pukb = pbf.read()

    pub_key = RSA.import_key(pukb)
    verifier = pkcs1_15.new(pub_key)

    hash_obj = SHA1.new(message.encode('utf8'))
    try:
        raw_sign = base64.b64decode(sign.encode('utf8'))
        verifier.verify(hash_obj, raw_sign)
        print('the sign is valid >>>>>>>>>>>>>>>>')
        return True
    except (ValueError, TypeError):
        print('The signature is invalid')
        return False


def encrypt_test(data):
    """
    测试RSA的加解密
    :param data:
    :return:
    """
    print('原始数据：', data)
    en_data = encrypt(data)
    print('加密后的数据：', en_data)
    de_data = decrypt(en_data)
    print('解密后的数据：', de_data)


def sign_test(content):
    """
    RSA算法的签名及验签测试
    :param content:
    :return:
    """
    print('原始数据：', content)
    sign= rsa_sign(content)
    print('原始签名：', sign)

    rsa_signverify(content, sign)


if __name__ == '__main__':
    # 测试纯英文字符
    encrypt_test('hello')
    print('=' * 15)
    # 测试全中文字符
    encrypt_test('大家一起学编程')
    print('=' * 15)
    # 测试中英混合字符
    encrypt_test('和我一起学Python')

    sign_test('hello')
    print('=' * 15)
    # 测试全中文字符
    sign_test('大家一起学编程')
    print('=' * 15)
    # 测试中英混合字符
    sign_test('和我一起学Python')
