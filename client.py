import requests
from requests.exceptions import RequestException
import json
from EncryptionHardwarePort import EncryptionHardwarePort
import base64
import hashlib
from typing import List, Dict
from flask import Flask, jsonify,request,Response

port = 'COM5'  # 串口号，Linux 下可能是 '/dev/ttyUSB0'
baudrate = 460800
# 服务器的地址和端口
# SERVER_URL  = "https://datafunder.zeabur.app"
# SERVER_PORT=8080
SERVER_URL  = "http://127.0.0.1:5000"
SERVER_PORT=5000
EP = EncryptionHardwarePort(port, baudrate)
key_id=0

class VerificationRequest:
    def __init__(self,request_id, request_public_key, verifier_public_key, verification_hash, hash_signature,verification_status):
        self.request_id=request_id
        self.verifier_public_key = verifier_public_key
        self.request_public_key = request_public_key
        self.verification_hash = verification_hash
        self.hash_signature = hash_signature
        self.verification_status = verification_status
        
    def verify(self) -> bool:
        # 这里应该实现实际的验证逻辑
        # 为了演示，我们假设验证总是成功
        self.verification_status = True
        return self.verification_status
    
    def to_json(self):
        return json.dumps({
            'request_id': self.request_id,
            'verifier_public_key': base64.b64encode(self.verifier_public_key).decode('utf-8'),
            'request_public_key': base64.b64encode(self.request_public_key).decode('utf-8'),
            'verification_hash': base64.b64encode(self.verification_hash).decode('utf-8'),
            'hash_signature': base64.b64encode(self.hash_signature).decode('utf-8'),
            'verification_status': self.verification_status
        })

    @classmethod
    def from_json(cls, json_data):
        # 如果 json_data 已经是一个字典，直接使用它
        if isinstance(json_data, dict):
            data = json_data
        else:
            # 否则，假设它是一个 JSON 字符串，并解析它
            data = json.loads(json_data)
        return cls(
            request_id=data['request_id'],
            request_public_key=base64.b64decode(data['request_public_key']),
            verifier_public_key=base64.b64decode(data['verifier_public_key']),
            verification_hash=base64.b64decode(data['verification_hash']),
            hash_signature=base64.b64decode(data['hash_signature']),
            verification_status=data['verification_status']
        )
 
verification_requests: List[VerificationRequest] = []

def connect_server(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # 如果响应状态码不是200，将抛出HTTPError异常
        print('请求成功')
        print(response.text)
        return response       
    except RequestException as e:
        print('请求失败：', e)
          

def send_key_to_server(key_id, key):
    key_base64 = base64.b64encode(key).decode('utf-8')
    data = {
        'key_id': key_id,
        'key': key_base64
    }
    response = requests.post(SERVER_URL+'/keys/', json=data)
    print(f"Server response: {response.text}")
    print(f"Status code: {response.status_code}")
    return response  


def send_verify_result_to_server(verification_request):

    data = {
        'request_id': verification_request.request_id,
        'verifier_public_key': base64.b64encode(verification_request.verifier_public_key).decode('utf-8'),
        'request_public_key': base64.b64encode(verification_request.request_public_key).decode('utf-8'),
        'verification_hash': base64.b64encode(verification_request.verification_hash).decode('utf-8'),
        'hash_signature': base64.b64encode(verification_request.hash_signature).decode('utf-8'),
        'verification_status': verification_request.verification_status
    }
    response = requests.post(SERVER_URL+'/verify_result/', json=data)
    print(f"Server response: {response.text}")
    print(f"Status code: {response.status_code}")
    return response  



def send_signature_request(public_key, verifier_hash,hash_signature):

    # 将签名转换为 Base64 编码的字符串
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')
    hash_signature_base64 = base64.b64encode(hash_signature).decode('utf-8')
    verifier_hash_base64=base64.b64encode(verifier_hash).decode('utf-8')
    data = {
        'public_key': public_key_base64,
        'verifier_hash': verifier_hash_base64,
        'hash_signature': hash_signature_base64
    }
    
    response = requests.post(SERVER_URL+'/verify_signature/', json=data)
    print(f"Server response: {response.text}")
    print(f"Status code: {response.status_code}")
    return response





if __name__ == '__main__':
    if EP.ser.isOpen():
        print(f"Opened {port} at {baudrate} baud")

        try:
            # # 检查响应是否全0
        
            public_key = EP.read_public_key(key_id)
            verifier_random=EP.output_random_number()
            verifier_hash =hashlib.sha256(verifier_random).digest()#生成哈希
            #verifier_hash =b'"\xf3\x06\xc3\x86F\x08 \xd3]r\xb0\xbcbZ \xcf*\xe6?\x96\x14\xb83Vd\xe5\xfe\x9d\xbd\xf3\x1e'#生成哈希

            print(f"hash==============={verifier_hash}")

            hash_signature=EP.sign_hash(key_id, verifier_hash)#生成哈希签名
           # hash_signature=b'l\xbc\x94\xe5A\x1df\xc6\x86\xcf8\x16\x88%\xd7c\\C\x8d[\x8dm\xa3\xd8\xdbX|N\xea]\xc0[8E7&C\xe2\xf1A\xe0\x8b=1\x17x\xfa\x83\x0c\x90\x95\xa5\xa2V\xe0\x8d\xc9]w\x9c)%\xa8\xb5'#生成哈希签名
            print(f"hash_signature==============={hash_signature}")
            
            response =connect_server(SERVER_URL)
            response =send_key_to_server(key_id, public_key)
            # if response is None:
            #     print("Failed to send key. Exiting.")
            #     return
            # print(f"Key sent. Response status code: {response.status_code}")
            # response_json = response.json()
            # print(f"Response JSON: {response_json}")
            
            if response.status_code == 200:
                response_json = response.json()
                print(f"Response JSON: {response_json}")
                #verification_request=VerificationRequest(response_json.get(""),)
                pending_request=response_json.get('pending_request')
                
                #print(f"test   request_id={request_id}")
                
                
                verification_request=VerificationRequest.from_json(pending_request)
                # print(f"verification_request.request_public_key={verification_request.request_public_key}")
                # print(f"verification_request.hash_signature={verification_request.hash_signature}")
                # print(f"verification_request.verification_hash={verification_request.verification_hash}")
                
                res=EP.verify_signature(verification_request.request_public_key,verification_request.hash_signature,verification_request.verification_hash)
                if(res==b'\x00'):
                    print(f"verification_FAILL")
                    verification_request.verification_status='FAILL'
                    send_verify_result_to_server(verification_request)
                elif(res==b'\x01'):
                    print(f"verification_OK")
                    verification_request.verification_status='OK'
                    send_verify_result_to_server(verification_request)

                    
                else:
                    print(f"res=={res}")
            response =send_signature_request(public_key,verifier_hash,hash_signature)



        except KeyboardInterrupt:
            print("Exiting...")

        finally:
            # 关闭串口
            EP.ser.close()
            print("Closed port")
    else:
        print("Failed to open port")




