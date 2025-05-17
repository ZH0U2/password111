import base64
import base58
import urllib.parse
import html
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import ttkbootstrap as tb
import datetime
import os

# ---- 加密算法实现 ----

# Base64
def base64_encode(t): return base64.b64encode(t.encode()).decode()
def base64_decode(t): return base64.b64decode(t.encode()).decode()

# Base32
def base32_encode(t): return base64.b32encode(t.encode()).decode()
def base32_decode(t): return base64.b32decode(t.encode()).decode()

# Base16
def base16_encode(t): return base64.b16encode(t.encode()).decode()
def base16_decode(t): return base64.b16decode(t.encode()).decode()

# Base58
def base58_encode(t): return base58.b58encode(t.encode()).decode()
def base58_decode(t): return base58.b58decode(t.encode()).decode()

# Hex
def hex_encode(t): return t.encode().hex()
def hex_decode(t): return bytes.fromhex(t).decode()

# URL
def url_encode(t): return urllib.parse.quote(t)
def url_decode(t): return urllib.parse.unquote(t)

# HTML
def html_encode(t): return html.escape(t)
def html_decode(t): return html.unescape(t)

# ASCII
def ascii_encode(t): return ' '.join(str(ord(c)) for c in t)
def ascii_decode(t): return ''.join(chr(int(i)) for i in t.split())

# 凯撒密码
def caesar_encrypt(t, k): return ''.join(chr((ord(c)+int(k))%256) for c in t)
def caesar_decrypt(t, k): return ''.join(chr((ord(c)-int(k))%256) for c in t)

# 栅栏密码
def rail_fence_encrypt(t): return t[::2] + t[1::2]
def rail_fence_decrypt(t):
    h = (len(t)+1)//2
    return ''.join(a+b for a,b in zip(t[:h], t[h:]+' '))[:len(t)]

# 摩斯密码
MORSE = {'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.',
         'H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.',
         'O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-',
         'V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',' ':'/'}
MORSE_REV = {v:k for k,v in MORSE.items()}
def morse_encode(t): return ' '.join(MORSE.get(c.upper(),'?') for c in t)
def morse_decode(t): return ''.join(MORSE_REV.get(c,'?') for c in t.split())

# 猪圈密码
PIGPEN = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ ", "⛒⛔⛐⛑⛓⛟⛛⛝⛙⛘⛕⛚⛎⛍⛉⛌⛃⛂⛁⛀⛇⛆⛅⛤⛥"))
PIGPEN_REV = {v:k for k,v in PIGPEN.items()}
def pigpen_encode(t): return ''.join(PIGPEN.get(c.upper(),'?') for c in t)
def pigpen_decode(t): return ''.join(PIGPEN_REV.get(c,'?') for c in t)

# 维吉尼亚密码
def vigenere_encrypt(t,k): return ''.join(chr((ord(c)+ord(k[i%len(k)]))%256) for i,c in enumerate(t))
def vigenere_decrypt(t,k): return ''.join(chr((ord(c)-ord(k[i%len(k)]))%256) for i,c in enumerate(t))

# AES文本加密解密（ECB模式）
def aes_encrypt(t,k):
    cipher = AES.new(k.encode(), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(t.encode(),16))).decode()
def aes_decrypt(t,k):
    cipher = AES.new(k.encode(), AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(t)),16).decode()

# DES文本加密解密（ECB模式）
def des_encrypt(t,k):
    cipher = DES.new(k.encode(), DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(t.encode(),8))).decode()
def des_decrypt(t,k):
    cipher = DES.new(k.encode(), DES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(t)),8).decode()

# DES文件加密解密
def des_encrypt_file(input_path, output_path, key):
    if len(key) != 8:
        raise ValueError("DES密钥必须是8字节")
    with open(input_path, "rb") as f:
        data = f.read()
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, 8))
    with open(output_path, "wb") as f:
        f.write(encrypted)

def des_decrypt_file(input_path, output_path, key):
    if len(key) != 8:
        raise ValueError("DES密钥必须是8字节")
    with open(input_path, "rb") as f:
        data = f.read()
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(data), 8)
    with open(output_path, "wb") as f:
        f.write(decrypted)

# AES文件加密解密（ECB模式）
def aes_encrypt_file(input_path, output_path, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES密钥长度必须是16/24/32字节")
    with open(input_path, "rb") as f:
        data = f.read()
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, 16))
    with open(output_path, "wb") as f:
        f.write(encrypted)

def aes_decrypt_file(input_path, output_path, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES密钥长度必须是16/24/32字节")
    with open(input_path, "rb") as f:
        data = f.read()
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(data), 16)
    with open(output_path, "wb") as f:
        f.write(decrypted)

# RSA 密钥和加解密
RSA_KEY = RSA.generate(1024)
RSA_CIPHER_ENC = PKCS1_OAEP.new(RSA_KEY.publickey())
RSA_CIPHER_DEC = PKCS1_OAEP.new(RSA_KEY)

def rsa_encrypt(t):
    return base64.b64encode(RSA_CIPHER_ENC.encrypt(t.encode())).decode()
def rsa_decrypt(t):
    return RSA_CIPHER_DEC.decrypt(base64.b64decode(t)).decode()

def rsa_export_private_key(path):
    with open(path, "wb") as f:
        f.write(RSA_KEY.export_key())

def rsa_export_public_key(path):
    with open(path, "wb") as f:
        f.write(RSA_KEY.publickey().export_key())

def rsa_import_private_key(path):
    global RSA_KEY, RSA_CIPHER_DEC, RSA_CIPHER_ENC
    with open(path, "rb") as f:
        RSA_KEY = RSA.import_key(f.read())
    RSA_CIPHER_DEC = PKCS1_OAEP.new(RSA_KEY)
    RSA_CIPHER_ENC = PKCS1_OAEP.new(RSA_KEY.publickey())

def rsa_import_public_key(path):
    global RSA_CIPHER_ENC
    with open(path, "rb") as f:
        pub_key = RSA.import_key(f.read())
    RSA_CIPHER_ENC = PKCS1_OAEP.new(pub_key)

# ---- 方法字典 ----
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

# ---- 日志记录 ----
def write_log(method, op, key, *args):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(f"[{now}] {method} - {op}\n")
        f.write(f"密钥: {key}\n")
        for i,arg in enumerate(args):
            f.write(f" {arg}\n")
        f.write("-"*40 + "\n")

# ---- GUI界面 ----
app = tb.Window(themename="superhero")
app.title("综合密码加解密工具")
app.geometry("780x700")

# 选择算法
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
            if method == "AES" and len(key) not in [16, 24, 32]:
                output_text.delete("1.0", tk.END)
                output_text.insert(tk.END, "AES密钥长度必须是16、24或32个字符")
                return
            if method == "DES" and len(key) != 8:
                output_text.delete("1.0", tk.END)
                output_text.insert(tk.END, "DES密钥长度必须是8个字符")
                return
            result = encode_func(text, key) if op == "加密" else decode_func(text, key)
        elif method == "RSA":
            result = encode_func(text) if op == "加密" else decode_func(text)
        else:
            result = encode_func(text) if op == "加密" else decode_func(text)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
        write_log(method, op, key, f"输入文本: {text}", f"结果: {result}")
    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"错误: {e}")

tb.Button(app, text="执行", bootstyle="success", command=process).pack(pady=10)

tb.Label(app, text="输出结果：", font=("Arial", 12)).pack()
output_text = tk.Text(app, height=6, font=("Courier", 11), relief="solid", bd=1)
output_text.pack(fill="both", expand=True, padx=10, pady=(5, 20))

# ---- RSA密钥导入导出 ----
def export_private_key():
    path = filedialog.asksaveasfilename(title="导出私钥", defaultextension=".pem", filetypes=[("PEM文件","*.pem")])
    if path:
        try:
            rsa_export_private_key(path)
            messagebox.showinfo("成功", f"私钥已导出到:\n{path}")
            write_log("RSA私钥导出", "导出", "", f"路径: {path}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

def export_public_key():
    path = filedialog.asksaveasfilename(title="导出公钥", defaultextension=".pem", filetypes=[("PEM文件","*.pem")])
    if path:
        try:
            rsa_export_public_key(path)
            messagebox.showinfo("成功", f"公钥已导出到:\n{path}")
            write_log("RSA公钥导出", "导出", "", f"路径: {path}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

def import_private_key():
    path = filedialog.askopenfilename(title="导入私钥", filetypes=[("PEM文件","*.pem")])
    if path:
        try:
            rsa_import_private_key(path)
            messagebox.showinfo("成功", f"私钥已导入:\n{path}")
            write_log("RSA私钥导入", "导入", "", f"路径: {path}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

def import_public_key():
    path = filedialog.askopenfilename(title="导入公钥", filetypes=[("PEM文件","*.pem")])
    if path:
        try:
            rsa_import_public_key(path)
            messagebox.showinfo("成功", f"公钥已导入:\n{path}")
            write_log("RSA公钥导入", "导入", "", f"路径: {path}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

frame_rsa = tb.Frame(app)
frame_rsa.pack(pady=5)
tb.Button(frame_rsa, text="导出私钥", bootstyle="info", command=export_private_key).pack(side="left", padx=10)
tb.Button(frame_rsa, text="导出公钥", bootstyle="info", command=export_public_key).pack(side="left", padx=10)
tb.Button(frame_rsa, text="导入私钥", bootstyle="secondary", command=import_private_key).pack(side="left", padx=10)
tb.Button(frame_rsa, text="导入公钥", bootstyle="secondary", command=import_public_key).pack(side="left", padx=10)

# ---- 文件加解密 ----

frame_file = tb.Frame(app)
frame_file.pack(pady=10)

def encrypt_file_aes():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = key_entry.get()
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("错误", "AES密钥长度必须为16、24或32个字符")
        return
    try:
        out_path = filedialog.asksaveasfilename(title="保存AES加密文件", defaultextension=".aes")
        if out_path:
            aes_encrypt_file(file_path, out_path, key)
            messagebox.showinfo("成功", f"文件已用AES加密保存到:\n{out_path}")
            write_log("文件加密(AES)", "加密", key, f"文件路径: {file_path}", f"保存路径: {out_path}")
    except Exception as e:
        messagebox.showerror("错误", str(e))

def decrypt_file_aes():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = key_entry.get()
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("错误", "AES密钥长度必须为16、24或32个字符")
        return
    try:
        out_path = filedialog.asksaveasfilename(title="保存AES解密文件")
        if out_path:
            aes_decrypt_file(file_path, out_path, key)
            messagebox.showinfo("成功", f"文件已用AES解密保存到:\n{out_path}")
            write_log("文件解密(AES)", "解密", key, f"文件路径: {file_path}", f"保存路径: {out_path}")
    except Exception as e:
        messagebox.showerror("错误", str(e))

def encrypt_file_des():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = key_entry.get()
    if len(key) != 8:
        messagebox.showerror("错误", "DES密钥长度必须为8个字符")
        return
    try:
        out_path = filedialog.asksaveasfilename(title="保存DES加密文件", defaultextension=".des")
        if out_path:
            des_encrypt_file(file_path, out_path, key)
            messagebox.showinfo("成功", f"文件已用DES加密保存到:\n{out_path}")
            write_log("文件加密(DES)", "加密", key, f"文件路径: {file_path}", f"保存路径: {out_path}")
    except Exception as e:
        messagebox.showerror("错误", str(e))

def decrypt_file_des():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    key = key_entry.get()
    if len(key) != 8:
        messagebox.showerror("错误", "DES密钥长度必须为8个字符")
        return
    try:
        out_path = filedialog.asksaveasfilename(title="保存DES解密文件")
        if out_path:
            des_decrypt_file(file_path, out_path, key)
            messagebox.showinfo("成功", f"文件已用DES解密保存到:\n{out_path}")
            write_log("文件解密(DES)", "解密", key, f"文件路径: {file_path}", f"保存路径: {out_path}")
    except Exception as e:
        messagebox.showerror("错误", str(e))

tb.Button(frame_file, text="加密文件(AES)", bootstyle="success", command=encrypt_file_aes).pack(side="left", padx=10)
tb.Button(frame_file, text="解密文件(AES)", bootstyle="danger", command=decrypt_file_aes).pack(side="left", padx=10)
tb.Button(frame_file, text="加密文件(DES)", bootstyle="success", command=encrypt_file_des).pack(side="left", padx=10)
tb.Button(frame_file, text="解密文件(DES)", bootstyle="danger", command=decrypt_file_des).pack(side="left", padx=10)

# ---- 运行 ----
app.mainloop()
