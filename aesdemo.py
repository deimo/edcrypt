import base64
import random
from Crypto.Cipher import AES


def pkcs7padding(text):
    """
    明文使用pkcs7填充
    即对于AES128,如果明文为”1234567890”一共10位,缺6位,
    采用PKCS7Padding方式填充之后的明文为“1234567890666666”
    :param text:  明文
    :return:
    """
    bs = AES.block_size
    length = len(text)
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    bytes_length = len(bytes(text, encoding="utf8"))
    padding_size = length if (bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    padding_text = chr(padding) * padding

    return text + padding_text


def pcks7unpadding(text):
    length = len(text)
    unpadding = ord(text[length - 1])

    return text[0: length - unpadding]


def pkcs7unpadding(text):
    length = len(text)
    unpadding = ord(text[length - 1])

    return text[0: length - unpadding]


def encrypt(key, content):
    """
    :param key:
    :param content:
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    # 重新编码
    result = str(base64.b64encode(encrypt_bytes), encoding='utf8')

    return result


def decrypt(key, content):
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # base64解码
    encrypt_bytes = base64.b64decode(content)
    # 解密
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    # 解码
    result = decrypt_bytes.decode('utf8')
    # 去除填充内容
    result = pkcs7unpadding(result)

    return result


def get_key(n):
    c_length = int(n)
    source = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    length = len(source) - 1
    result = ''
    for i in range(c_length):
        result += source[random.randint(0, length)]

    return result


def test():
    aes_key = get_key(16)
    print('aes_key: ', aes_key)

    # 对英文加密
    source_en = 'Hello'
    print('原始字符串：', source_en)
    encrypt_en = encrypt(aes_key, source_en)
    print('加密后：', encrypt_en)
    # 对英文解密
    decrypt_en = decrypt(aes_key, encrypt_en)
    print('解密后：', decrypt_en)
    print('==' * 10)

    # 中英文混合加密
    source_mixed = 'Hello, 卡尔大神！'
    print('原始字符串: ', source_mixed)
    encrypt_mixed = encrypt(aes_key, source_mixed)
    print('加密后：', encrypt_mixed)
    # 解密
    decrypt_mixed = decrypt(aes_key, encrypt_mixed)
    print('解密后：', decrypt_mixed)
    print('==' * 10)

    # 刚好16字节的情况
    en_16 = 'abcdefgj10124567'
    print('原始字符串：', en_16)
    encrypt_en = encrypt(aes_key, en_16)
    print('加密后：', encrypt_en)
    # 解密
    decrypt_en = decrypt(aes_key, encrypt_en)
    print('解密后：', decrypt_en)
    print('==' * 10)

    # 中英文一起刚好16字节
    mix_16 = 'hhh张三丰12sa'
    print('原始字符串：', mix_16)
    encrypt_mixed = encrypt(aes_key, mix_16)
    print('加密后：', encrypt_mixed)
    decrypt_mixed = decrypt(aes_key, encrypt_mixed)
    print('解密后：', decrypt_mixed)


if __name__ == '__main__':
    test()
