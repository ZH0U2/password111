import base64, urllib.parse, html
import tkinter as tk
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ttkbootstrap as tb

# 加密算法实现
# base64
def base64_encode(t): return base64.b64encode(t.encode()).decode()
def base64_decode(t): return base64.b64decode(t.encode()).decode()
# base32
def base32_encode(t): return base64.b32encode(t.encode()).decode()
def base32_decode(t): return base64.b32decode(t.encode()).decode()
# base16
def base16_encode(t): return base64.b16encode(t.encode()).decode()
def base16_decode(t): return base64.b16decode(t.encode()).decode()
# base58
def base58_encode(t): return base58.b58encode(t.encode()).decode()
def base58_decode(t): return base58.b58decode(t.encode()).decode()
# hex
def hex_encode(t): return t.encode().hex()
def hex_decode(t): return bytes.fromhex(t).decode()
# url
def url_encode(t): return urllib.parse.quote(t)
def url_decode(t): return urllib.parse.unquote(t)
# html
def html_encode(t): return html.escape(t)
def html_decode(t): return html.unescape(t)
# ascii
def ascii_encode(t): return ' '.join(str(ord(c)) for c in t)
def ascii_decode(t): return ''.join(chr(int(i)) for i in t.split())
# 凯撒
def caesar_encrypt(t, k): return ''.join(chr((ord(c)+int(k))%256) for c in t)
def caesar_decrypt(t, k): return ''.join(chr((ord(c)-int(k))%256) for c in t)

def rail_fence_encrypt(t): return t[::2]+t[1::2]
def rail_fence_decrypt(t): h=(len(t)+1)//2; return ''.join(a+b for a,b in zip(t[:h],t[h:]+' '))[:len(t)]
# 摩斯
MORSE = {'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..',
         'J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.',
         'S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',' ':'/'}
MORSE_REV = {v:k for k,v in MORSE.items()}
def morse_encode(t): return ' '.join(MORSE.get(c.upper(),'?') for c in t)
def morse_decode(t): return ''.join(MORSE_REV.get(c,'?') for c in t.split())
# 猪圈
PIGPEN = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ ", "⛒⛔⛐⛑⛓⛟⛛⛝⛙⛘⛕⛚⛎⛍⛉⛌⛃⛂⛁⛀⛇⛆⛅⛤⛥"))
PIGPEN_REV = {v:k for k,v in PIGPEN.items()}
def pigpen_encode(t): return ''.join(PIGPEN.get(c.upper(),'?') for c in t)
def pigpen_decode(t): return ''.join(PIGPEN_REV.get(c,'?') for c in t)
# 维吉尼亚
def vigenere_encrypt(t,k): return ''.join(chr((ord(c)+ord(k[i%len(k)]))%256) for i,c in enumerate(t))
def vigenere_decrypt(t,k): return ''.join(chr((ord(c)-ord(k[i%len(k)]))%256) for i,c in enumerate(t))
# AES
def aes_encrypt(t,k): c=AES.new(k.encode(), AES.MODE_ECB); return base64.b64encode(c.encrypt(pad(t.encode(),16))).decode()
def aes_decrypt(t,k): c=AES.new(k.encode(), AES.MODE_ECB); return unpad(c.decrypt(base64.b64decode(t)),16).decode()
# DES
def des_encrypt(t,k): c=DES.new(k.encode(), DES.MODE_ECB); return base64.b64encode(c.encrypt(pad(t.encode(),8))).decode()
def des_decrypt(t,k): c=DES.new(k.encode(), DES.MODE_ECB); return unpad(c.decrypt(base64.b64decode(t)),8).decode()
# RSA
import base58
RSA_KEY = RSA.generate(1024)
RSA_CIPHER_ENC = PKCS1_OAEP.new(RSA_KEY.publickey())
RSA_CIPHER_DEC = PKCS1_OAEP.new(RSA_KEY)
def rsa_encrypt(t): return base64.b64encode(RSA_CIPHER_ENC.encrypt(t.encode())).decode()
def rsa_decrypt(t): return RSA_CIPHER_DEC.decrypt(base64.b64decode(t)).decode()

methods = {
    "Base64": (base64_encode, base64_decode),
    "Base32": (base32_encode, base32_decode),
    "Base16": (base16_encode, base16_decode),
    "Base58": (base58_encode, base58_decode),
    "Hex": (hex_encode, hex_decode),
    "URL编码": (url_encode, url_decode),
    "HTML编码": (html_encode, html_decode),
    "ASCII码": (ascii_encode, ascii_decode),
    "摩斯密码": (morse_encode, morse_decode),
    "凯撒密码": (caesar_encrypt, caesar_decrypt),
    "栅栏密码": (rail_fence_encrypt, rail_fence_decrypt),
    "猪圈密码": (pigpen_encode, pigpen_decode),
    "维吉尼亚密码": (vigenere_encrypt, vigenere_decrypt),
    "AES": (aes_encrypt, aes_decrypt),
    "DES": (des_encrypt, des_decrypt),
    "RSA": (rsa_encrypt, rsa_decrypt)
}

app = tb.Window(themename="superhero")
app.title("密码加解密工具")
app.geometry("700x600")

method_var = tk.StringVar(value="Base64")
op_var = tk.StringVar(value="加密")

tb.Label(app, text="选择加密方式：", font=("Arial", 12)).pack(pady=(10,0))
method_menu = tb.Combobox(app, textvariable=method_var, values=list(methods.keys()), width=30)
method_menu.pack()

tb.Label(app, text="操作类型：", font=("Arial", 12)).pack(pady=(10,0))
op_menu = tb.Combobox(app, textvariable=op_var, values=["加密", "解密"], width=30)
op_menu.pack()

tb.Label(app, text="密钥（如需）：", font=("Arial", 12)).pack(pady=(10,0))
key_entry = tb.Entry(app, width=40)
key_entry.pack()

tb.Label(app, text="输入文本：", font=("Arial", 12)).pack(pady=(10,0))
input_text = tk.Text(app, height=6, font=("Courier", 11), relief="solid", bd=1)
input_text.pack(fill="both", expand=True, padx=10, pady=5)

def process():
    method = method_var.get()
    op = op_var.get()
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get()
    if not text:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "请输入内容")
        return
    try:
        encode_func, decode_func = methods[method]
        if method in ["AES", "DES", "凯撒密码", "维吉尼亚密码"]:
            if not key:
                output_text.delete("1.0", tk.END)
                output_text.insert(tk.END, "需要密钥")
                return
            result = encode_func(text, key) if op == "加密" else decode_func(text, key)
        elif method == "RSA":
            result = encode_func(text) if op == "加密" else decode_func(text)
        else:
            result = encode_func(text) if op == "加密" else decode_func(text)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"错误: {e}")

tb.Button(app, text="执行", bootstyle="success", command=process).pack(pady=10)

tb.Label(app, text="输出结果：", font=("Arial", 12)).pack()
output_text = tk.Text(app, height=6, font=("Courier", 11), relief="solid", bd=1)
output_text.pack(fill="both", expand=True, padx=10, pady=(5, 20))

app.mainloop()
