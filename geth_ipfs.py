#/usr/bin/env python
#-*- coding:utf-8 -*-
from web3 import Web3, HTTPProvider
import ipfshttpclient
from cryptography import fernet#用于对称加密
from umbral import pre,keys,signing,config,params,kfrags,cfrags
import os
from socket import *
import pickle
from hexbytes import HexBytes
import requests
import json
import threading

config.set_default_curve()#设置非加密方式，默认secp256k1
THRESHOLD=2#default threshold number
SPLIT_NUMBER=2#default split_frag number
class ETHConnectionError(Exception):
    def __init__(self,message):
        self.msg=message
    def __str__(self):
        print("APIConnection Error:",self.msg)
#信息包结构
class info_packet():
    def __init__(self,capsule=None,pub_key1=None,pub_key2=None,verify_key=None,tx_hash=None,kfrag=None,cfrag=None,IP=None,selfport=None,check=None):
        self.info={"capsule":capsule,
                   "pub_key1":pub_key1,
                   "pub_key2":pub_key2,
                   "verify_key":verify_key,
                   "tx_hash":tx_hash,
                   "kfrag":kfrag,
                   "cfrag":cfrag,
                   "IP":IP,
                   "selfport":selfport,
                   "check":check}

class node():
    curve = params.Curve(714)
    def __init__(self,eth_api,ipfs_api):
        self.w3 = Web3(HTTPProvider(eth_api))#以太坊geth客户端接口
        #print(self.w3)
        if not self.w3.isConnected():
            raise ETHConnectionError("区块链未连接")
        self.client = ipfshttpclient.connect(ipfs_api)#ipfs接口
        self.port=7001#数据帧接收端口

        self.record={}
        #json 文件加载
        if os.path.exists("data.pkl"):
            param=params.UmbralParameters(self.curve)
            with open("data.pkl","rb") as f:
                records=pickle.load(f)
                for record in records:
                    #record也许需要处理一下
                    for key in record.keys():
                        capsule=pre.Capsule.from_bytes(record[key],param)
                        record[key]=capsule
                        self.record.update(record)

        print("Already get record:",self.record)
        self.tempo_cfrags={}#暂时接收来自其他节点的cfrag帧
        sock_ip_get = socket(AF_INET, SOCK_DGRAM)
        sock_ip_get.connect(('8.8.8.8', 80))
        ip = sock_ip_get.getsockname()[0]
        self.IP=ip
        print("Host Information:",self.IP,":",self.port)


    def key_create(self):
        if not os.path.exists("key_pair.pkl"):
            key_pair={}
            self.key=fernet.Fernet.generate_key()#对称加密密钥
            #创建节点非对称加密的私钥与公钥
            self.pri_key=keys.UmbralPrivateKey.gen_key()
            self.pub_key=self.pri_key.get_pubkey()
            #创造数字签名用私钥与公钥
            self.signing_key = keys.UmbralPrivateKey.gen_key()
            self.verifying_key=self.signing_key.get_pubkey()
            self.signer = signing.Signer(self.signing_key)
            #保存,二值化处理
            key_pair["key"]=self.key
            key_pair["pri_key"]=self.pri_key.to_bytes()
            key_pair["pub_key"]=self.pub_key.to_bytes()
            key_pair["signing_key"]=self.signing_key.to_bytes()
            key_pair["verifying_key"]=self.verifying_key.to_bytes()
            with open("key_pair.pkl","wb") as f:
                pickle.dump(key_pair,f)
                print("the key pair has been saved")

        else:
            with open("key_pair.pkl","rb") as f:
                key_pair=pickle.load(f)
                pub_key=keys.UmbralPublicKey.from_bytes(key_pair["pub_key"])
                verifying_key=keys.UmbralPublicKey.from_bytes(key_pair["verifying_key"])
                pri_key=keys.UmbralPrivateKey.from_bytes(key_pair["pri_key"])
                signing_key=keys.UmbralPrivateKey.from_bytes(key_pair["signing_key"])
                self.key=key_pair["key"]
                self.pri_key=pri_key
                self.pub_key=pub_key
                self.signing_key=signing_key
                self.verifying_key=verifying_key
                self.signer=signing.Signer(self.signing_key)
                print("the key pair loads success")



    def IP_FIND(self):
        '''
        返回发送目标地址
        :return:
        '''
        IP=[]
        peers_info=self.client.swarm.peers()['Peers']
        for peer in peers_info:
            ip = peer['Addr'].split("/")[2]
            IP.append(ip)
        return IP


    def send(self,packet,des_IP):
        '''
        数据帧统一发送函数
        :param packet:
        :param des_IP:
        :param des_port:
        :return:
        '''
        packet=pickle.dumps(packet)
        sk=socket(AF_INET,SOCK_STREAM,0)
        sk.connect((des_IP,7001))
        sk.sendall(packet)
        sk.close()






    def receive(self):
        
        
        
        
        #获取本地IP
        
        sock_receiver=socket(AF_INET,SOCK_STREAM,0)
        sock_receiver.bind((self.IP,self.port))
        sock_receiver.listen(10)
        sock_receiver.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        #监听端口配置

        while True:
            conn,address=sock_receiver.accept()
            #获得发送方IP地址和端口
            total_data=[]
            while True:
                data=conn.recv(1024)
                if not data:break
                total_data.append(data)

            data_receive=b''.join(total_data)
            obj=pickle.loads(data_receive)
            #数据接收


            if isinstance(obj,info_packet):
                if obj.info["check"]==2:#接收到公钥
                    capsule=self.record[obj.info["tx_hash"]]
                    pub_key = keys.UmbralPublicKey.from_bytes(obj.info["pub_key1"])
                    print("接收到公钥：",pub_key)
                    kfrags_=pre.generate_kfrags(self.pri_key,pub_key,THRESHOLD,SPLIT_NUMBER,self.signer)
                    #序列化
                    capsule = capsule.to_bytes()
                    pub_key1=pub_key.to_bytes()#目标公钥
                    pub_key2=self.pub_key.to_bytes()#自身公钥
                    verify_key=self.verifying_key.to_bytes()#验证公钥
                    IP=self.IP_FIND()#可连接IP
                    #IP处理
                    if obj.info["IP"] in IP:
                        IP.remove(obj.info["IP"])
                    if len(IP)>=THRESHOLD:
                        for i,kfrag in enumerate(kfrags_):
                            kfrag = kfrag.to_bytes()
                            responce = info_packet(capsule=capsule, kfrag=kfrag, tx_hash=obj.info["tx_hash"],
                                                IP=obj.info["IP"],pub_key1=pub_key1,pub_key2=pub_key2,verify_key=verify_key,check=3)
                            
                            self.send(packet=responce,des_IP=IP[i%len(IP)])


                elif obj.info["check"]==0:
                    #接收到初始请求
                    # capsule二值化
                    print("received the request")
                    capsule=self.record[obj.info["tx_hash"]]
                    capsule=capsule.to_bytes()
                    # 自身公钥二值化
                    print(capsule)
                    pub_key2=self.pub_key.to_bytes()
                    verify_key=self.verifying_key.to_bytes()
                    responce=info_packet(capsule=capsule,tx_hash=obj.info["tx_hash"],check=1,IP=self.IP,pub_key2=pub_key2,verify_key=verify_key)
                    print(obj.info["IP"])
                    self.send(packet=responce,des_IP=obj.info["IP"])

                elif obj.info["check"]==1:
                    #接收到请求确认
                    #capsule还原
                    capsule=obj.info["capsule"]
                    param = params.UmbralParameters(self.curve)
                    capsule = pre.Capsule.from_bytes(capsule,param)
                    #公钥还原
                    pub_key2 = obj.info["pub_key2"]
                    pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
                    verify_key = obj.info["verify_key"]
                    verify_key = keys.UmbralPublicKey.from_bytes(verify_key)
                    capsule.set_correctness_keys(pub_key2,self.pub_key,verify_key)
                    self.record[obj.info["tx_hash"]]=capsule
                    pub_key=self.pub_key.to_bytes()
                    responce=info_packet(tx_hash=obj.info["tx_hash"],IP=self.IP,pub_key1=pub_key,check=2)
                    self.send(packet=responce,des_IP=obj.info["IP"])



                elif obj.info["check"]==3:#接收到重加密碎片
                    #kfrag处理
                    kfrag=obj.info["kfrag"]
                    kfrag=kfrags.KFrag.from_bytes(kfrag)
                    #capsule处理
                    capsule=obj.info["capsule"]
                    param = params.UmbralParameters(self.curve)
                    capsule = pre.Capsule.from_bytes(capsule, param)
                    #公钥处理
                    pub_key1 = obj.info["pub_key1"]
                    pub_key1=keys.UmbralPublicKey.from_bytes(pub_key1)
                    pub_key2 = obj.info["pub_key2"]
                    pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
                    verify_key = obj.info["verify_key"]
                    verify_key = keys.UmbralPublicKey.from_bytes(verify_key)

                    #重加密
                    capsule.set_correctness_keys(pub_key2,pub_key1,verify_key)
                    print(capsule)
                    cfrag=pre.reencrypt(kfrag,capsule)
                    print("CFrag完成",cfrag)
                    #cfrag处理
                    cfrag=cfrag.to_bytes()
                    cfrag_packet=info_packet(cfrag=cfrag,tx_hash=obj.info["tx_hash"])
                    self.send(packet=cfrag_packet, des_IP=obj.info["IP"])



                elif obj.info["cfrag"]!=None:
                    print("收到cfrag数据帧")
                    if obj.info["tx_hash"] not in self.tempo_cfrags:
                        #cfrag处理
                        print("开始累积cfrag")
                        temp=obj.info["cfrag"]
                        temp=cfrags.CapsuleFrag.from_bytes(temp)
                        self.tempo_cfrags[obj.info["tx_hash"]]=[temp]
                        #print(self.tempo_cfrags)
                        if len(self.tempo_cfrags[obj.info["tx_hash"]])>=THRESHOLD:
                            #开始解密
                            capsule=self.record[obj.info["tx_hash"]]
                            for cfrag in self.tempo_cfrags[obj.info["tx_hash"]]:
                                capsule.attach_frag(cfrag)
                            self.file_download_and_decrypt(obj.info["tx_hash"],capsule)
                        #删除记录

                    else:
                        temp = obj.info["cfrag"]
                        temp = cfrags.CapsuleFrag.from_bytes(temp)
                        self.tempo_cfrags[obj.info["tx_hash"]].append(temp)
                        if len(self.tempo_cfrags[obj.info["tx_hash"]]) >= THRESHOLD:
                            # 开始解密
                            print(self.tempo_cfrags[obj.info["tx_hash"]])
                            capsule = self.record[obj.info["tx_hash"]]
                            print(capsule)
                            for cfrag in self.tempo_cfrags[obj.info["tx_hash"]]:
                                capsule.attach_cfrag(cfrag)
                            print("开始解密")
                            self.file_download_and_decrypt(obj.info["tx_hash"], capsule)








    def file_encrypt_and_upload(self,file):
        #file代表文件位置
        #该函数处理数据加密以及上传至ipfs以及区块链的功能
        with open(file,"rb") as f:
            data=f.read()

            encrpted_file=fernet.Fernet(self.key).encrypt(data)

            with open("%s_encrypted"%file,"wb") as f_:
                f_.write(encrpted_file)

        res=self.client.add("%s_encrypted"%file)
        #删除加密文件,防止积累
        os.remove("./%s_encrypted"%file)
        upload=[]#可能需要加密
        upload.append(res['Hash'])

        key=str(self.key,encoding="utf-8")

        upload.append(key)
        upload=" ".join(upload)#上链字符串数据
        print(upload)
        ciphertext,capsule=pre.encrypt(self.pub_key,bytes(upload,encoding="utf-8"))
        #print(ciphertext)
        #可能需要非对称加密
        upload_data=self.w3.toHex(ciphertext)
        txo = {}
        txo['from'] = self.w3.eth.accounts[0]
        txo['to'] = self.w3.eth.accounts[1]
        txo['value'] = self.w3.toHex(0)
        txo['data'] = upload_data
        self.w3.geth.personal.unlockAccount(self.w3.eth.accounts[0], "123456")
        transaction_hash = self.w3.eth.sendTransaction(txo)#交易hash可以以数据库形式存储
        self.w3.geth.miner.start()
        self.w3.eth.waitForTransactionReceipt(transaction_hash)
        self.w3.geth.miner.stop()
        print("成功上链")
        #建立交易哈希与capsule的键值关系,保存至json文件
        #self.record[transaction_hash]=capsule
        capsule=capsule.to_bytes()#capsule
        #print(type(capsule))
        #transaction_hash=transaction_hash.hex()
        data={transaction_hash:capsule}
        print(data)
        if not os.path.exists("data.pkl"):
            list=[]
            with open("data.pkl","wb") as f:
                list.append(data)
                pickle.dump(list,f)
        else:
            fr=open("data.pkl","rb")
            old_pickle=pickle.load(fr)
            fr.close()
            old_pickle.append(data)
            with open("data.pkl","wb") as f:
                pickle.dump(old_pickle,f)
        data={"IP":self.IP,"tx_hash":transaction_hash.hex()}
        responce=requests.post(url="http://10.134.205.182:8085/sendjson",json=data,verify=False)
        if responce.status_code==200:
            print("上传完毕")



    
        





    def file_download_and_decrypt(self,tx_hash,capsule):
        tx=self.w3.eth.getTransaction(tx_hash)
        print(tx)
        ciphertext=self.w3.toBytes(hexstr=tx['input'])
        print(ciphertext)
        cleartext=pre.decrypt(ciphertext,capsule,self.pri_key)
        ipfs_hash=cleartext.decode("utf-8")
        print(ipfs_hash)
        ipfs_hash=ipfs_hash.split(" ")
        print(ipfs_hash)
        #self.client.get(ipfs_hash[0])
        encrypt_res=self.client.cat(ipfs_hash[0])
        print(encrypt_res)
        decrypt_res=fernet.Fernet(bytes(ipfs_hash[1],"utf-8")).decrypt(encrypt_res)
        file=decrypt_res.decode("utf-8")
        print(file)
        print("接收成功")


if __name__=="__main__":
    
    eth_api="http://10.134.205.182:8545"
    ipfs_api="/ip4/127.0.0.1/tcp/5001"
    node= node(eth_api, ipfs_api)
    node.key_create()
    print("开始文件传输测试")
    print(node.pri_key)
    print(node.pub_key)
    print(type(node.key))
    print(type(node.pub_key))

    #t=threading.Thread(target=node.receive)
    #t.start()
    #node.file_encrypt_and_upload("test1.txt")
    #node.file_encrypt_and_upload("test.txt") 
    

    

  


    

    





