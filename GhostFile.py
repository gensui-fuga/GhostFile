#!/usr/bin/env python3
"""
文件多层加密/解密工具（伪装 + 压缩 + 零宽隐写）
加密流程：zlib压缩 → 凯撒字节移位 → AES-256-CBC → Base64 → 零宽字符编码 → 嵌入伪装文字
用法：
  伪装加密：python GhostFile.py -w <文字或文件> <待加密文件>
  普通加密：python GhostFile.py <待加密文件>
  解    密：python GhostFile.py -d <加密文件>
"""

import sys
import os
import zlib
import hashlib
import secrets
import base64
from getpass import getpass
from typing import Optional

# AES 依赖
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    sys.exit("错误：请先安装 pycryptodome →  pip install pycryptodome")

# ============== 凯撒字节位移 ==============
CAESAR_SHIFT = 13

def caesar_encrypt(data: bytes) -> bytes:
    return bytes((b + CAESAR_SHIFT) % 256 for b in data)

def caesar_decrypt(data: bytes) -> bytes:
    return bytes((b - CAESAR_SHIFT) % 256 for b in data)

# ============== AES‑256‑CBC ==============
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt,
                               PBKDF2_ITERATIONS, dklen=KEY_SIZE)

def aes_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size))

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# ============== 零宽隐写 ==============
ZW_0 = '\u200b'  # 零宽空格（表示比特 0）
ZW_1 = '\u200c'  # 零宽不连字符（表示比特 1）
ZW_MARKER = ZW_0 * 8 + ZW_1 * 8  # 开始标记

def binary_to_zwsp(data: bytes) -> str:
    bits = ''.join(f'{byte:08b}' for byte in data)
    return ''.join(ZW_0 if b == '0' else ZW_1 for b in bits)

def zwsp_to_binary(zw_text: str) -> bytes:
    bits = [ch for ch in zw_text if ch in (ZW_0, ZW_1)]
    byte_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]
    byte_vals = []
    for chunk in byte_chunks:
        if len(chunk) == 8:
            bits_str = ''.join('0' if c == ZW_0 else '1' for c in chunk)
            byte_vals.append(int(bits_str, 2))
    return bytes(byte_vals)

# ============== 核心加密 / 解密 ==============
def encrypt_file(filepath: str, password: str, cover_text: Optional[str] = None) -> None:
    with open(filepath, 'rb') as f:
        plain_data = f.read()

    # 第0层：zlib 压缩（减少最终零宽文件体积）
    compressed = zlib.compress(plain_data)

    # 第1层：凯撒
    caesar_data = caesar_encrypt(compressed)

    # 第2层：AES
    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    key = derive_key(password, salt)
    aes_cipher = aes_encrypt(caesar_data, key, iv)

    # 组装加密包：salt + iv + 压缩标志(1字节) + AES密文
    encrypted_package = salt + iv + b'\x01' + aes_cipher

    if cover_text is not None:
        # 伪装模式：Base64 → 零宽编码 → 嵌入伪装文字
        b64 = base64.b64encode(encrypted_package)
        zw_data = ZW_MARKER + binary_to_zwsp(b64)
        final_content = cover_text + zw_data
        out_path = filepath + '.enc'
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print(f'✅ 伪装加密成功 → {out_path}')
        print(f'   记事本打开仅显示：“{cover_text}”')
    else:
        # 普通二进制 .enc
        out_path = filepath + '.enc'
        with open(out_path, 'wb') as f:
            f.write(encrypted_package)
        print(f'✅ 加密成功 → {out_path}')
    print('   密码请务必牢记。')

def decrypt_file(filepath: str, password: str) -> None:
    # 尝试读取为伪装文件（UTF-8文本）
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        marker_idx = content.find(ZW_MARKER)
        if marker_idx != -1:
            # 是伪装文件
            zw_seq = content[marker_idx + len(ZW_MARKER):]
            b64_bytes = zwsp_to_binary(zw_seq)
            package = base64.b64decode(b64_bytes)
        else:
            raise ValueError("未找到零宽标记")
    except (UnicodeDecodeError, ValueError):
        # 普通二进制加密文件
        with open(filepath, 'rb') as f:
            package = f.read()

    # 解析加密包
    salt = package[:SALT_SIZE]
    iv = package[SALT_SIZE:SALT_SIZE+IV_SIZE]
    compressed_flag = package[SALT_SIZE+IV_SIZE]
    aes_cipher = package[SALT_SIZE+IV_SIZE+1:]

    if len(salt) != SALT_SIZE or len(iv) != IV_SIZE:
        sys.exit("错误：文件格式不正确或已损坏。")

    key = derive_key(password, salt)
    try:
        caesar_data = aes_decrypt(aes_cipher, key, iv)
    except ValueError:
        sys.exit("错误：密码错误或文件已损坏，解密失败。")

    # 凯撒解密
    compressed = caesar_decrypt(caesar_data)

    # 根据标志决定是否解压
    if compressed_flag == 0x01:
        try:
            original_data = zlib.decompress(compressed)
        except zlib.error:
            sys.exit("错误：解压失败，文件可能已损坏或密码错误。")
    else:
        original_data = compressed  # 兼容无压缩旧格式

    out_path = filepath[:-4] if filepath.endswith('.enc') else filepath + '.dec'
    if os.path.exists(out_path):
        sys.exit(f"错误：输出文件 {out_path} 已存在，请先手动处理。")
    with open(out_path, 'wb') as f:
        f.write(original_data)
    print(f'✅ 解密成功 → {out_path}')

# ============== 命令行接口 ==============
def get_cover_text(arg: str) -> str:
    """智能判断：arg 若是文件路径则读取内容，否则直接作为伪装文字"""
    if os.path.isfile(arg):
        try:
            with open(arg, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            sys.exit(f"错误：无法读取伪装文字文件 {arg} → {e}")
    return arg

def main():
    if len(sys.argv) < 2:
        print('用法：')
        print(f'  伪装加密: {sys.argv[0]} -w <文字或文件> <待加密文件>')
        print(f'  普通加密: {sys.argv[0]} <待加密文件>')
        print(f'  解    密: {sys.argv[0]} -d <加密文件>')
        sys.exit(1)

    if '-d' in sys.argv:
        idx = sys.argv.index('-d')
        if len(sys.argv) != idx + 2:
            sys.exit('解密用法: ' + sys.argv[0] + ' -d <加密文件>')
        file_path = sys.argv[idx + 1]
        if not os.path.isfile(file_path):
            sys.exit(f'错误：文件 {file_path} 不存在')
        pwd = getpass('请输入解密密码: ')
        decrypt_file(file_path, pwd)
        return

    if '-w' in sys.argv:
        idx = sys.argv.index('-w')
        if len(sys.argv) < idx + 3:
            sys.exit('伪装加密用法: ' + sys.argv[0] + ' -w <文字或文件> <待加密文件>')
        cover_arg = sys.argv[idx + 1]
        file_path = sys.argv[idx + 2]
        cover_text = get_cover_text(cover_arg)
        if not os.path.isfile(file_path):
            sys.exit(f'错误：待加密文件 {file_path} 不存在')
        pwd = getpass('请设置加密密码: ')
        if len(pwd) == 0:
            sys.exit('错误：密码不能为空。')
        pwd_confirm = getpass('请再次输入密码确认: ')
        if pwd != pwd_confirm:
            sys.exit('错误：两次密码输入不一致。')
        encrypt_file(file_path, pwd, cover_text)
        return

    # 普通加密
    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        sys.exit(f'错误：文件 {file_path} 不存在')
    pwd = getpass('请设置加密密码: ')
    if len(pwd) == 0:
        sys.exit('错误：密码不能为空。')
    pwd_confirm = getpass('请再次输入密码确认: ')
    if pwd != pwd_confirm:
        sys.exit('错误：两次密码输入不一致。')
    encrypt_file(file_path, pwd)

if __name__ == '__main__':
    main()
