import base64
import hashlib
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
import os

def _get_sid(username):
    """Get SID for the current user"""
    import win32security
    sid, domain, type = win32security.LookupAccountName(None, username)
    return win32security.ConvertSidToStringSid(sid)

class Xsh:
    USER = os.getlogin()
    SID = _get_sid(USER)
                               
    def __init__(
        self,
        ip: str,
        username: str,
        port: int = 22,
        *,
        password: str | None = None,
        execute_cmd: str | None = None
    ):
        self.ip = ip
        self.username = username
        self.port = port
        self.execute_cmd = execute_cmd
        if password is None:
            raise ValueError('Missing parameter')
        else:
            self.password = password

        # self.USER = os.getlogin()
        # self.SID = _get_sid(self.USER)

    def __str__(self) -> str:
        if not self.execute_cmd:
            return f"""[SessionInfo]
Version=8.1
[CONNECTION]
Port={self.port}
Host={self.ip}
[CONNECTION:AUTHENTICATION]
Password={self.pwd_encrypt(self.password) if self.password else ''}
UserName={self.username}"""
        else:
            return f"""[SessionInfo]
Version=8.1
[CONNECTION]
Port={self.port}
Host={self.ip}
[CONNECTION:AUTHENTICATION]
ExpectSend_Expect_0=$
ExpectSend_Send_0={self.execute_cmd}
Password={self.pwd_encrypt(self.password) if self.password else ''}
UseExpectSend=1
ExpectSend_Count=1
UserName={self.username}"""
    
    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def pwd_decrypt(password: str) -> str:
        """解密密码"""
        str1 = Xsh.USER[::-1] + Xsh.SID
        str2 = str1[::-1]   # 字符串倒序
        data = base64.b64decode(password)  # b64解码
        hash_object = hashlib.sha256()  # sha256编码
        hash_object.update(bytes(str2, 'gbk'))
        key = hash_object.digest()
        pass_data = data[:(len(data)-32)]
        decrypted = ARC4.new(key).decrypt(pass_data)  # RC4加密
        return decrypted.decode()

    @staticmethod
    def pwd_encrypt(password: str) -> str:
        """加密密码"""
        # print(f"Encrypting password for user: {Xsh.USER}, SID: {Xsh.SID}")
        str1 = Xsh.USER[::-1] + Xsh.SID
        str2 = str1[::-1]   # 字符串倒序
        hash_object = hashlib.sha256()  # sha256编码
        hash_object.update(bytes(str2, 'gbk'))
        key = hash_object.digest()
        cipher = ARC4.new(key)  # RC4加密
        encrypted = cipher.encrypt(bytes(password, 'utf-8'))  # 加密
        # data = encrypted + b'\x00' * (32 - len(encrypted) % 32)  # 填充到32字节
        encoded = base64.b64encode(encrypted + SHA256.new(password.encode()).digest())  # b64编码
        return encoded.decode()
    
if __name__ == "__main__":
    p = '123456'
    print(Xsh.pwd_encrypt(p))
    print(Xsh.pwd_decrypt('R4ecAkXgjZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI='))
    print(Xsh.pwd_decrypt('vPYZsjiojZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI='))
    print(Xsh.pwd_decrypt('MJIsPpERjZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI='))