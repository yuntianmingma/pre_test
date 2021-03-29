# /usr/bin/env python
# -*- coding:utf-8 -*-

import ipfshttpclient
from cryptography import fernet
from umbral import pre, keys, signing, config, params, kfrags, cfrags
import os
from socket import *
import pickle
from hexbytes import HexBytes
import requests
import copy
import time
import threading
from queue import PriorityQueue
from random import shuffle
from collections import defaultdict
config.set_default_curve()
# default curve secp256k1
THRESHOLD = 2  # default threshold number
SPLIT_NUMBER = 2  # default split_frag number
MAX_LEVAL=10
'''
尚待解决：Tu、To更新，初始化问题
'''




# dataframe structure
class info_packet:
    def __init__(self, capsule=None, pub_key1=None, pub_key2=None, verify_key=None, kfrag=None,
                 cfrag=None, CID=None,IP=None, selfport=None, check=None,leval=None,ttl=None):
        self.info = {"capsule": capsule,
                     "pub_key1": pub_key1,
                     "pub_key2": pub_key2,
                     "verify_key": verify_key,
                     "kfrag": kfrag,
                     "cfrag": cfrag,
                     "CID":CID,
                     "IP": IP,
                     "selfport": selfport,
                     "check": check,
                     "leval":leval,
                     "ttl":ttl}

#neighbor node state,this is independent with the
class stat_packet:

    def __init__(self,id,To,Tu,state):

        self.info={"id":id,"To":To,"Tu":Tu,"state":state}#record the neighbors state
        #state:0：空闲 1：正常 2：过载









# Node designed to finish the encryption task
class node(object):
    curve = params.Curve(714)
    def __init__(self, ipfs_api,leval):
        self.client = ipfshttpclient.connect(ipfs_api)
        # Connection with the IPFS HTTP-Interface
        self.port = 7001
        # The task-receiving port
        self.record = {}
        # the capsule with the CID
        # load the json file
        if os.path.exists("data.pkl"):
            param = params.UmbralParameters(self.curve)
            with open("data.pkl", "rb") as f:
                records = pickle.load(f)
                for record in records:
                    # record记录的二进制capsule反序列化
                    for key in record.keys():
                        capsule = pre.Capsule.from_bytes(record[key], param)
                        record[key] = capsule
                        self.record.update(record)

        print("Already get record:", self.record)

        # Receiving cfrag from other node
        self.tempo_cfrags = {}

        #Get the local IP
        sock_ip_get = socket(AF_INET, SOCK_DGRAM)
        sock_ip_get.connect(('8.8.8.8', 80))
        ip = sock_ip_get.getsockname()[0]
        self.IP = ip
        print("Host Information:", self.IP, ":", self.port)
        #the task queue
        self.task_queue=PriorityQueue()
        #the load state of the neighbor node
        self.neighbor_state=defaultdict(list)
        self.state=stat_packet(id=self.client.id()['ID'],To=10,Tu=3,state=0)
        self.leval=leval
        self.lock=threading.Lock()
        self.local=threading.local()
        self.time_dict=defaultdict(float)
        self.update_flag=0


    def key_create(self):
        #创建以及保存非对称密钥，对称密钥由加密时产生
        #create the key-config file or load the key-config file
        #the symmetrical key will be temporarily created when file upload the IPFS
        if not os.path.exists("key_pair.pkl"):
            key_pair = {}

            # create asymmetrical key for the node,this is unique for each node
            self.pri_key = keys.UmbralPrivateKey.gen_key()
            self.pub_key = self.pri_key.get_pubkey()
            # create the key for digital signature
            self.signing_key = keys.UmbralPrivateKey.gen_key()
            self.verifying_key = self.signing_key.get_pubkey()
            self.signer = signing.Signer(self.signing_key)
            # save the keys as binary file
            key_pair["pri_key"] = self.pri_key.to_bytes()
            key_pair["pub_key"] = self.pub_key.to_bytes()
            key_pair["signing_key"] = self.signing_key.to_bytes()
            key_pair["verifying_key"] = self.verifying_key.to_bytes()
            with open("key_pair.pkl", "wb") as f:
                pickle.dump(key_pair, f)
                print("the key pair has been saved")

        else:
            with open("key_pair.pkl", "rb") as f:
                key_pair = pickle.load(f)
                pub_key = keys.UmbralPublicKey.from_bytes(key_pair["pub_key"])
                verifying_key = keys.UmbralPublicKey.from_bytes(key_pair["verifying_key"])
                pri_key = keys.UmbralPrivateKey.from_bytes(key_pair["pri_key"])
                signing_key = keys.UmbralPrivateKey.from_bytes(key_pair["signing_key"])
                self.pri_key = pri_key
                self.pub_key = pub_key
                self.signing_key = signing_key
                self.verifying_key = verifying_key
                self.signer = signing.Signer(self.signing_key)
                print("the key pair loads success")

    def IP_FIND(self):
        '''
        get the IP and ID of neighbor node
        :return:
        IP:ID
        '''
        IP_ID = {}
        peers_info = self.client.swarm.peers()['Peers']
        for peer in peers_info:
            ip = peer['Addr'].split("/")[2]
            id= peer['Peer']#获取id
            ip_id={ip:id}
            IP_ID.update(ip_id)
        return IP_ID

    def send(self, packet, des_IP):
        '''
        dataframe sending function
        :param packet:可序列化对象
        :param des_IP:目的节点IP
        :param des_port:目的端口
        :return:
        '''
        packet = pickle.dumps(packet)
        sk = socket(AF_INET, SOCK_STREAM, 0)
        sk.connect((des_IP, 7001))
        sk.sendall(packet)
        sk.close()
    def handle_request(self,obj):
        #处理任务信息
        #我们规定请求方为pub1,拥有方为pub2
        if(obj.info["check"==0]):
            print("received the request")
            capsule = self.record[obj.info["CID"]]
            capsule = capsule.to_bytes()
            pub_key2 = self.pub_key.to_bytes()
            verify_key = self.verifying_key.to_bytes()
            responce = info_packet(capsule=capsule, CID=obj.info["CID"], check=1, IP=self.IP,
                                   pub_key2=pub_key2, verify_key=verify_key)

            self.send(packet=responce, des_IP=obj.info["IP"])
        elif(obj.info["check"]==1):
            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)
            # 公钥还原
            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)
            capsule.set_correctness_keys(pub_key2, self.pub_key, verify_key)
            self.record[obj.info["CID"]] = capsule
            pub_key = self.pub_key.to_bytes()
            responce = info_packet(CID=obj.info["CID"], IP=self.IP, pub_key1=pub_key, check=2,ttl=0,leval=self.leval)
            self.send(packet=responce, des_IP=obj.info["IP"])

        elif(obj.info["check"]==2):
            capsule = self.record[obj.info["CID"]]
            pub_key1 = keys.UmbralPublicKey.from_bytes(obj.info["pub_key1"])
            kfrags_ = pre.generate_kfrags(self.pri_key, pub_key1, THRESHOLD, SPLIT_NUMBER, self.signer)
            # 序列化
            capsule = capsule.to_bytes()
            pub_key1 = pub_key1.to_bytes()  # 目标公钥
            pub_key2 = self.pub_key.to_bytes()  # 自身公钥
            verify_key = self.verifying_key.to_bytes()  # 验证公钥
            IP_ID = self.IP_FIND()
            IP_ID=shuffle(list(IP_ID.items()))
            # IP处理,根据节点状态逐级选择转移或者接收
            #kfrag逐级发送给不同状态节点
            assert len(IP_ID)>=THRESHOLD
            visited_id = set()
            for kfrag in kfrags_:
                kfrag = kfrag.to_bytes()

                for ip,id in IP_ID:
                    if id not in visited_id:

                        if(self.neighbor_state[id][2]==0 and ip!=obj.info["IP"]):
                            packet=info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                           IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                           verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"])#添加ttl和leval
                            self.send(packet,ip)
                            visited_id.add(id)
                            break
                        elif(self.neighbor_state[id][2]==1 and ip!=obj.info["IP"]):
                            packet = info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                             IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                             verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"])
                            self.send(packet, ip)
                            visited_id.add(id)
                            break
                        elif(self.neighbor_state[id][2]==2 and ip!=obj.info["IP"]):
                            packet = info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                             IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                             verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"])
                            self.send(packet, ip)
                            visited_id.add(id)
                            break




        elif(obj.info["check"]==3):

            # 转移设置考虑

            if(self.state.info['state']==2):#过载状态
                ip_id=self.IP_FIND()
                ip_id=shuffle(list(ip_id.items()))
                for ip,id in ip_id:
                    if(self.neighbor_state[id][2]==0 and ip!=obj.info["IP"]):#空闲转移
                        #增加ttl
                        obj.info["ttl"]+=1
                        self.send(obj,ip)
                        break
                    elif(self.neighbor_state[id][2]==1 and ip!=obj.info["IP"]):#正常转移
                        obj.info["ttl"] += 1
                        self.send(obj,ip)
                        break
                    elif(self.neighbor_state[id][2]==2 and ip!=obj.info["IP"]):#过载转移
                        obj.info["ttl"] += 1
                        self.send(obj, ip)
                        break


            #任务处理
            else:
                #进入任务队列,计算优先度参数
                #T转发次数，S停留时间，节点等级

                task_old_count=self.task_queue.qsize()
                #任务值更新，增加1,需要加锁

                self.lock.acquire()
                for i in range(self.task_queue.qsize()):
                    a=self.task_queue.get()
                    a[0]+=1
                    self.task_queue.put(a)
                prior_value=obj.info["ttl"]+0+obj.info["leval"]/MAX_LEVAL#ttl和leval的传递问题
                obj=(prior_value,obj)
                self.task_queue.put(obj)
                self.lock.release()
                #查看是否存在状态变化
                if(self.task_queue.qsize()>self.state.info["To"] and task_old_count<=self.state.info["To"]):
                    #发布状态变更消息
                    ip_id=self.IP_FIND()
                    for ip,id in ip_id:
                        packet=stat_packet(id=self.state.info["id"],To=self.state.info["To"],Tu=self.state.info["Tu"],state=2)
                        self.send(packet,ip)
                elif(self.task_queue.qsize()>self.state.info["Tu"] and task_old_count<=self.state.info["Tu"]):
                    #发布状态变更消息
                    ip_id = self.IP_FIND()
                    for ip, id in ip_id:
                        packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"],
                                             Tu=self.state.info["Tu"], state=1)
                        self.send(packet,ip)

        elif obj.info["cfrag"] != None:
            print("收到cfrag数据帧")
            if obj.info["CID"] not in self.tempo_cfrags:
                # cfrag处理
                print("开始累积cfrag")
                temp = obj.info["cfrag"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                self.tempo_cfrags[obj.info["CID"]] = [temp]
                # print(self.tempo_cfrags)
                if len(self.tempo_cfrags[obj.info["CID"]]) >= THRESHOLD:
                    # 开始解密
                    capsule = self.record[obj.info["CID"]]
                    for cfrag in self.tempo_cfrags[obj.info["CID"]]:
                        capsule.attach_frag(cfrag)
                    self.file_download_and_decrypt(obj.info["CID"], capsule)
                # 删除记录

            else:
                temp = obj.info["cfrag"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                self.tempo_cfrags[obj.info["CID"]].append(temp)
                if len(self.tempo_cfrags[obj.info["CID"]]) >= THRESHOLD:
                    # 开始解密
                    print(self.tempo_cfrags[obj.info["CID"]])
                    capsule = self.record[obj.info["CID"]]
                    print(capsule)
                    for cfrag in self.tempo_cfrags[obj.info["CID"]]:
                        capsule.attach_cfrag(cfrag)
                    print("开始解密")
                    self.file_download_and_decrypt(obj.info["CID"], capsule)
    def handle_statinfo(self,obj):
        #处理邻居信息
        self.neighbor_state[obj.info["id"]]=[obj.info["To"],obj.info["Tu"],obj.info["state"]]
    def receive(self):
        sock_receiver = socket(AF_INET, SOCK_STREAM, 0)
        sock_receiver.bind((self.IP, self.port))
        sock_receiver.listen(10)
        sock_receiver.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # set the receving socket

        #启动计时,每3min更新状态
        #time_monitor=threading.Timer(60*3,self.update_state)
        #time_monitor.start()
        while True:
            conn, address = sock_receiver.accept()
            # establish connection
            total_data = []
            while True:
                data = conn.recv(1024)
                if not data: break
                total_data.append(data)

            data_receive = b''.join(total_data)
            obj = pickle.loads(data_receive)
            # data receiving

            #handle the message of different type
            if isinstance(obj, info_packet):
                self.handle_request(obj)
            if isinstance(obj,stat_packet):
                self.handle_statinfo(obj)




    def file_encrypt_and_upload(self, file):
        # file代表文件位置
        # 该函数处理数据加密以及上传至ipfs以及区块链的功能
        # 随机生成对称密钥
        #得到由文件CID和对应capsule的pkl文件
        symmetric_key = fernet.Fernet.generate_key()
        with open(file, "rb") as f:
            data = f.read()
            encrpted_file = fernet.Fernet(symmetric_key).encrypt(data)#文件对称加密
            encrypted_key, capsule = pre.encrypt(self.pub_key, symmetric_key)
            print(encrypted_key)
            upload=encrpted_file+b"   "+encrypted_key
            res=self.client.add_bytes(upload)
            print(res, capsule)
            data_now={res:capsule}
            self.record.update(data_now)
            capsule=capsule.to_bytes()

            #保存capsule，和CID并建立它们保存它们键值对的pkl文件
            data={res:capsule}

            if not os.path.exists("data.pkl"):
                list = []
                with open("data.pkl", "wb") as f:
                    list.append(data)
                    pickle.dump(list, f)
                    print("文件上传成功")
            else:
                fr = open("data.pkl", "rb")
                old_pickle = pickle.load(fr)
                fr.close()
                old_pickle.append(data)
                with open("data.pkl", "wb") as f:
                    pickle.dump(old_pickle, f)
                    print("文件上传成功")












    def file_download_and_decrypt(self, CID,capsule):
        encrypt_data = self.client.cat(CID).split(b"   ")#二进制数据
        file_data=encrypt_data[0]
        key_data=encrypt_data[1]

        key_clear_data=pre.decrypt(key_data, capsule, self.pri_key)
        decrypt_res = fernet.Fernet(key_clear_data).decrypt(file_data)
        file = decrypt_res.decode("utf-8")
        print(file)
        print("接收成功")
    def self_decrypt(self,CID):

        encrypt_data=self.client.cat(CID).split(b"   ")#问题很大

        capsule=self.record[CID]
        print(CID,capsule)
        file_date = encrypt_data[0]
        key_data = encrypt_data[1]
        print(key_data)
        key_clear_data=pre.decrypt(key_data,capsule,self.pri_key)
        decrypt_res=fernet.Fernet(key_clear_data).decrypt(file_date)
        file = decrypt_res.decode("utf-8")
        print(file)
        print("自我下载成功")
    def worker(self):
        #处理队列任务
        while True:
            self.lock.acquire()
            obj=self.task_queue.get(block=True)
            #查看是否存在状态变化
            self.lock.release()
            obj=obj[1]
            kfrag = obj.info["kfrag"]
            kfrag = kfrags.KFrag.from_bytes(kfrag)
            # capsule处理
            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)
            # 公钥处理
            pub_key1 = obj.info["pub_key1"]
            pub_key1 = keys.UmbralPublicKey.from_bytes(pub_key1)
            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)

            # 重加密
            capsule.set_correctness_keys(pub_key2, pub_key1, verify_key)
            print(capsule)
            cfrag = pre.reencrypt(kfrag, capsule)
            print("CFrag完成", cfrag)
            # cfrag处理
            cfrag = cfrag.to_bytes()
            cfrag_packet = info_packet(cfrag=cfrag, CID=obj.info["CID"])
            self.send(packet=cfrag_packet, des_IP=obj.info["IP"])
    def update_state(self):
        #好像需要加锁
        print("更新节点状态参数")
        #计算均值：
        self.update_flag=1
        time.sleep(1)
        alpha=8
        beta=4
        sum_To=0
        sum_Tu=0
        neighbor_state=copy.deepcopy(self.neighbor_state)
        for key,value in neighbor_state.items():
            sum_To+=value[0]
            sum_Tu+=value[1]
        avg_To=sum_To/len(neighbor_state)
        avg_Tu=sum_Tu/len(neighbor_state)
        #更改To、Tu
        time_overload_rate=self.time_dict[2]/3
        time_underload_rate=self.time_dict[0]/3
        if(self.state.info["To"]<avg_To):
            self.state.info["To"]+=alpha
            # 自身判定,过载时间超过50%
            if(time_overload_rate>0.5):
                self.state.info["To"]-=beta

        if(self.state.info["Tu"]<avg_Tu):
            self.state.info["Tu"] +=alpha
            #自身判定，空闲时间过长
            if(time_underload_rate>0.5):
                self.state.info["Tu"] += beta

        #更新自身状态
        if(self.task_queue.qsize()>self.state.info["To"]):
            self.state.info["state"]=2
        elif(self.task_queue.qsize()<self.state.info["Tu"]):
            self.state.info["state"] =0
        else:
            self.state.info["state"] =1
        #告知邻居节点
        ip_id = self.IP_FIND()
        for ip, id in ip_id:
            packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"],
                                 Tu=self.state.info["Tu"], state=self.state.info["state"])
            self.send(packet, ip)
        self.update_flag=0
        time_monitor = threading.Timer(60 * 3, self.update_state)
        time_monitor.start()
    def time_monitor(self):

        timer_thread1 = threading.Thread(target=self.time_calcu,args=(0,))
        timer_thread2 = threading.Thread(target=self.time_calcu,args=(1,))
        timer_thread3 = threading.Thread(target=self.time_calcu,args=(2,))
        timer_thread1.setDaemon(True)
        timer_thread2.setDaemon(True)
        timer_thread3.setDaemon(True)
        timer_thread1.start()
        timer_thread2.start()
        timer_thread3.start()
    def time_calcu(self,monitor_state):
        self.local.sum_=0
        while True:
            if(self.state.info["state"] == monitor_state):
                time1=time.time()
                while(self.state.info["state"] == monitor_state):
                    pass
                time2=time.time()
                self.local.sum_+=time2-time1

            if(self.update_flag==1):
                self.time_dict[monitor_state]=self.local.sum_
                break
        self.time_calcu(monitor_state)





















if __name__ == "__main__":

    ipfs_api = "/ip4/127.0.0.1/tcp/5002"
    node = node(ipfs_api,4)
    node.key_create()
    print("开始文件传输测试")
    #node.file_encrypt_and_upload("test.txt")
    print(node.record)
    node.self_decrypt(list(node.record.keys())[2])


















