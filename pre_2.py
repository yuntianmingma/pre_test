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
from random import shuffle,random
from collections import defaultdict
from collections import deque
import hashlib
import math
config.set_default_curve()
# default curve secp256k1
THRESHOLD = 2  # default threshold number
SPLIT_NUMBER = 3  # default split_frag number
MAX_LEVAL=10
log=[]



# dataframe structure
class info_packet:
    def __init__(self, capsule=None, pub_key1=None, pub_key2=None, verify_key=None, kfrag=None,
                 cfrag=None, CID=None,IP=None, selfport=None, check=None,leval=None,ttl=None,version=None):
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
                     "ttl":ttl,
                     "version":version,
                     }

#neighbor node state,this is independent with the
class stat_packet:

    def __init__(self,id,To,Tu,state):

        self.info={"id":id,"To":To,"Tu":Tu,"state":state}#record the neighbors state
        #state:0:free 1:normal 2:overload









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
        self.state=stat_packet(id=self.client.id()['ID'],To=20,Tu=10,state=0)
        self.leval=leval
        self.index=0
        self.lock=threading.Lock()
        self.lock2=threading.Lock()
        self.lock3=threading.Lock()
        self.local=threading.local()
        self.time_dict=defaultdict(float)
        self.update_flag=0
        self.old_version=set()
        self.handled_kfrag_number=0
        self.time_stat1=None
        self.time_stat2=None
        self.finish_files=0


    def key_create(self):
        
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
            id= peer['Peer']
            ip_id={ip:id}
            IP_ID.update(ip_id)
        return IP_ID

    def send(self, packet, des_IP):
        '''
        dataframe sending function
        :param packet:
        :param des_IP:
        :param des_port:
        :return:
        '''
        packet = pickle.dumps(packet)
        sk = socket(AF_INET, SOCK_STREAM, 0)
        sk.connect((des_IP, 7001))
        sk.sendall(packet)
        sk.close()
    def handle_request(self,obj):
        
        #user is pub1,data owner is pub2
        if(obj.info["check"]==0):
            print("received the request")
            capsule = self.record[obj.info["CID"]]
            capsule = capsule.to_bytes()
            pub_key2 = self.pub_key.to_bytes()
            verify_key = self.verifying_key.to_bytes()
            responce = info_packet(capsule=capsule, CID=obj.info["CID"], check=1, IP=self.IP,
                                   pub_key2=pub_key2, verify_key=verify_key)

            self.send(packet=responce, des_IP=obj.info["IP"])
        elif(obj.info["check"]==1):
            print("receive the response")
            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)
            
            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)
            capsule.set_correctness_keys(pub_key2, self.pub_key, verify_key)
            if obj.info["CID"] in self.record:
                self.record[obj.info["CID"]].append(capsule)
            else:
                self.record[obj.info["CID"]] = [capsule]
            pub_key = self.pub_key.to_bytes()
            responce = info_packet(CID=obj.info["CID"], IP=self.IP, pub_key1=pub_key, check=2,ttl=0,leval=self.leval)
            self.send(packet=responce, des_IP=obj.info["IP"])

        elif(obj.info["check"]==2):
            print("dispatch the kfrag")
            capsule = self.record[obj.info["CID"]]
            pub_key1 = keys.UmbralPublicKey.from_bytes(obj.info["pub_key1"])
            kfrags_ = pre.generate_kfrags(self.pri_key, pub_key1, THRESHOLD, SPLIT_NUMBER, self.signer)
            capsule = capsule.to_bytes()
            pub_key1 = pub_key1.to_bytes()  
            pub_key2 = self.pub_key.to_bytes()
            verify_key = self.verifying_key.to_bytes()
            IP_ID = self.IP_FIND()
            version=hashlib.sha256(str(time.time()).encode("utf-8")).hexdigest()
            #print(version,obj.info["IP"],obj.info["CID"])
             
            
            visited_id =deque(maxlen=len(IP_ID))
            for kfrag in kfrags_:
                    kfrag = kfrag.to_bytes()
                    flag=0

                    for ip,id in IP_ID.items():
                        if id not in visited_id:

                            if(self.neighbor_state[id][2]==0 and ip!=obj.info["IP"]):
                                packet=info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                               IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                               verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"],version=version)
                                self.send(packet,ip)
                                visited_id.append(id)
                                if(len(visited_id)==len(IP_ID)):
                                     visited_id.clear()
                                flag=1
                                break
                    if(flag==0):
                        for ip,id in IP_ID.items():
                            if id not in visited_id:

                                if(self.neighbor_state[id][2]==1 and ip!=obj.info["IP"]):
                                    packet=info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                                   IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                                   verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"],version=version)
                                    self.send(packet,ip)
                                    visited_id.append(id)
                                    if(len(visited_id)==len(IP_ID)):
                                        visited_id.clear()
                                    flag=1
                                    break
                    if(flag==0):
                        for ip,id in IP_ID.items():
                            if id not in visited_id:

                                if(self.neighbor_state[id][2]==2 and ip!=obj.info["IP"]):
                                    packet=info_packet(capsule=capsule, kfrag=kfrag, CID=obj.info["CID"],
                                                   IP=obj.info["IP"], pub_key1=pub_key1, pub_key2=pub_key2,
                                                   verify_key=verify_key, check=3,ttl=0,leval=obj.info["leval"],version=version)
                                    self.send(packet,ip)
                                    visited_id.append(id)
                                    if(len(visited_id)==len(IP_ID)):
                                            visited_id.clear()
                                    flag=1
                                    break



        elif(obj.info["check"]==3):
            print("get the kfrag")
            self.lock3.acquire()
            #time.sleep(0.3)

            if(self.state.info['state']==2):
                ip_id=self.IP_FIND()
                flag=0
                random_node=list(ip_id.items())
                shuffle(random_node)
                for ip,id in random_node:
                    if(self.neighbor_state[id][2]==0 and ip!=obj.info["IP"]):
                        #add ttl
                        obj.info["ttl"]+=1
                        self.send(obj,ip)
                        flag=1
                        break

                if(flag==0):
                    for ip,id in random_node:
                        if(self.neighbor_state[id][2]==1 and ip!=obj.info["IP"]):
                        #add ttl
                            obj.info["ttl"]+=1
                            self.send(obj,ip)
                            flag=1
                            break
                
                if(flag==0):
                    for ip,id in random_node:
                        if(self.neighbor_state[id][2]==2 and ip!=obj.info["IP"]):
                        #add ttl
                            obj.info["ttl"]+=1
                            self.send(obj,ip)
                            
                            break
                


            
            else:
                
                
                self.lock.acquire()
                #old_va=self.task_queue.qsize()
                temp_list=[]
                for i in range(self.task_queue.qsize()):
                    a=self.task_queue.get()
                    temp_list.append(a)

                for i in range(len(temp_list)):
                    temp_list[i][0]-=1
                    self.task_queue.put(temp_list[i])
                    
                prior_value=obj.info["ttl"]+0+obj.info["leval"]
                obj=[-prior_value,self.index,obj]
                self.task_queue.put(obj)
                self.index+=1
                print("current task number:",self.task_queue.qsize())
                
                
                
                

                if(self.task_queue.qsize()==self.state.info["To"]+5):
                    
                    self.state.info["state"]=2
                    #self.lock.release()
                    ip_id=self.IP_FIND()
                    for ip,id in ip_id.items():
                        packet=stat_packet(id=self.state.info["id"],To=self.state.info["To"],Tu=self.state.info["Tu"],state=2)
                        self.send(packet,ip)
                elif(self.task_queue.qsize()==self.state.info["Tu"]+5):
                    
                    self.state.info['state']=1
                    #self.lock.release()
                    ip_id = self.IP_FIND()
                    for ip, id in ip_id.items():
                        packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"],
                                             Tu=self.state.info["Tu"], state=1)
                        self.send(packet,ip)
                
                self.lock.release()
            self.lock3.release()

        elif obj.info["cfrag"] != None:
            self.lock2.acquire()
            print("receive cfrag...........")
            if obj.info["version"] in self.old_version:
                self.lock2.release()
                return
            if obj.info["CID"] not in self.tempo_cfrags:
                # cfrag handle
                print("accumulating cfrag.............")
                temp = obj.info["cfrag"]
                version=obj.info["version"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                self.tempo_cfrags[obj.info["CID"]] = {version:[temp]}
                # print(self.tempo_cfrags)
                
                

            else:
                
                temp = obj.info["cfrag"]
                version=obj.info["version"]
                temp = cfrags.CapsuleFrag.from_bytes(temp)
                if version in self.tempo_cfrags[obj.info["CID"]]:
                    self.tempo_cfrags[obj.info["CID"]][version].append(temp)
                
                else:
                    self.tempo_cfrags[obj.info["CID"]][version]=[temp]

                if len(self.tempo_cfrags[obj.info["CID"]][version]) >= THRESHOLD:
                    
                    #print(self.tempo_cfrags[obj.info["CID"]])
                    capsule = self.record[obj.info["CID"]].pop()
                    #print(capsule)
                    for cfrag in self.tempo_cfrags[obj.info["CID"]][version]:
                        capsule.attach_cfrag(cfrag)
                    print("begin decrypting")
                    self.file_download_and_decrypt(obj.info["CID"], capsule)
                    self.tempo_cfrags[obj.info["CID"]].pop(version)
                    self.old_version.add(version)
            self.lock2.release()



    def handle_statinfo(self,obj):
        print("receiving the neighbor state:",obj.info["id"],"\n")
        self.neighbor_state[obj.info["id"]]=[obj.info["To"],obj.info["Tu"],obj.info["state"]]
    def receive(self):
        sock_receiver = socket(AF_INET, SOCK_STREAM, 0)
        sock_receiver.bind((self.IP, self.port))
        sock_receiver.listen(10)
        sock_receiver.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # set the receving socket

        
        
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
                threading.Thread(target=self.handle_request,args=(obj,)).start()
            if isinstance(obj,stat_packet):
                threading.Thread(target=self.handle_statinfo,args=(obj,)).start()




    def file_encrypt_and_upload(self, file):
        
        symmetric_key = fernet.Fernet.generate_key()
        with open(file, "rb") as f:
            data = f.read()
            encrpted_file = fernet.Fernet(symmetric_key).encrypt(data)
            encrypted_key, capsule = pre.encrypt(self.pub_key, symmetric_key)
            print(encrypted_key)
            upload=encrpted_file+b"   "+encrypted_key
            res=self.client.add_bytes(upload)
            print(res, capsule)
            data_now={res:capsule}
            self.record.update(data_now)
            capsule=capsule.to_bytes()

            
            data={res:capsule}

            if not os.path.exists("data.pkl"):
                list = []
                with open("data.pkl", "wb") as f:
                    list.append(data)
                    pickle.dump(list, f)
                    print("file upload sucess")
            else:
                fr = open("data.pkl", "rb")
                old_pickle = pickle.load(fr)
                fr.close()
                old_pickle.append(data)
                with open("data.pkl", "wb") as f:
                    pickle.dump(old_pickle, f)
                    print("file upload success")












    def file_download_and_decrypt(self, CID,capsule):
        encrypt_data = self.client.cat(CID).split(b"   ")
        file_data=encrypt_data[0]
        key_data=encrypt_data[1]

        key_clear_data=pre.decrypt(key_data, capsule, self.pri_key)
        decrypt_res = fernet.Fernet(key_clear_data).decrypt(file_data)
        file = decrypt_res.decode("utf-8")
        print(file)
        print("receive success")
        self.finish_files+=1
        if(self.finish_files==50):
            self.time_stat2=time.time()
            print("--------finish ,time is ",self.time_stat2-self.time_stat1)
            print(log)

    def self_decrypt(self,CID):

        encrypt_data=self.client.cat(CID).split(b"   ")

        capsule=self.record[CID]
        print(CID,capsule)
        file_date = encrypt_data[0]
        key_data = encrypt_data[1]
        print(key_data)
        key_clear_data=pre.decrypt(key_data,capsule,self.pri_key)
        decrypt_res=fernet.Fernet(key_clear_data).decrypt(file_date)
        file = decrypt_res.decode("utf-8")
        print(file)
        print("self download sucess")
    def worker(self):
        
        while True:
            if(self.task_queue.empty()):
                print("Waiting...........")
                time.sleep(0.3)
                continue
            #obj=self.task_queue.get(block=True)
            self.lock.acquire()
            #old_value=self.task_queue.qsize()
            obj=self.task_queue.get(block=True)
            print("get a task")
            if(self.task_queue.qsize()==self.state.info["To"]-5):
                self.state.info["state"]=1
                #self.lock.release()
                ip_id=self.IP_FIND()
                for ip,id in ip_id.items():
                    packet=stat_packet(id=self.state.info["id"],To=self.state.info["To"],Tu=self.state.info["Tu"],state=1)
                    self.send(packet,ip)
            elif(self.task_queue.qsize()==self.state.info["Tu"]-5):
                    print("Free State")
                    self.state.info['state']=0
                    #self.lock.release()
                    ip_id = self.IP_FIND()
                    for ip, id in ip_id.items():
                        packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"],
                                             Tu=self.state.info["Tu"], state=0)
                        self.send(packet,ip)
            
            self.lock.release()
            time.sleep(0.3)
            obj=obj[2]
            kfrag = obj.info["kfrag"]
            kfrag = kfrags.KFrag.from_bytes(kfrag)
               
            capsule = obj.info["capsule"]
            param = params.UmbralParameters(self.curve)
            capsule = pre.Capsule.from_bytes(capsule, param)
                
            pub_key1 = obj.info["pub_key1"]
            pub_key1 = keys.UmbralPublicKey.from_bytes(pub_key1)
            pub_key2 = obj.info["pub_key2"]
            pub_key2 = keys.UmbralPublicKey.from_bytes(pub_key2)
            verify_key = obj.info["verify_key"]
            verify_key = keys.UmbralPublicKey.from_bytes(verify_key)

               
            capsule.set_correctness_keys(pub_key2, pub_key1, verify_key)
            print(capsule)
            cfrag = pre.reencrypt(kfrag, capsule)
            print("CFrag finish", cfrag)
               
            cfrag = cfrag.to_bytes()
            
            cfrag_packet = info_packet(cfrag=cfrag, CID=obj.info["CID"],version=obj.info["version"])
            self.send(packet=cfrag_packet, des_IP=obj.info["IP"])
            self.handled_kfrag_number+=1
            print(self.handled_kfrag_number)
                
                
    def update_state(self):
        
        print("Update State")
        #AVG:
        #self.update_flag=1
        #time for handling the time_monitor
        #time.sleep(1)
        self.lock.acquire()
        sum_To=0
        sum_Tu=0
        neighbor_state=copy.deepcopy(self.neighbor_state)
        for key,value in neighbor_state.items():
            sum_To+=value[0]
            sum_Tu+=value[1]
        avg_To=sum_To/len(neighbor_state)
        avg_Tu=sum_Tu/len(neighbor_state)
        print("node6",avg_Tu)
        print("node6",avg_To)
        #update ToÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â£ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚ÂTu
        '''time_overload_rate=self.time_dict[2]/sum(self.time_dict.values())
        print("time_overload_rate:",time_overload_rate)
        time_underload_rate=self.time_dict[0]/sum(self.time_dict.values())
        print("time_underload_rate:",time_underload_rate)'''
        old_To=self.state.info["To"]
        old_Tu=self.state.info["Tu"]
        #if(old_To<avg_To):
        self.state.info["To"]+=(avg_To-old_To)*0.5
        '''if(time_overload_rate>0.9):
            self.state.info["To"]-=(old_To-old_Tu)*(time_overload_rate-0.9)'''
        
        #self.state.info["To"]=math.ceil(self.state.info["To"])
        #if(old_Tu<avg_Tu):
        self.state.info["Tu"] +=(avg_Tu-old_Tu)*0.5
        '''if(time_underload_rate>0.9):
            self.state.info["Tu"]+=(old_To-old_Tu)*(time_underload_rate-0.9)
            self.state.info["To"]+=(old_To-old_Tu)*(time_underload_rate-0.9)'''
        self.state.info["Tu"]=math.ceil(self.state.info["Tu"])
        self.state.info["To"]=math.ceil(self.state.info["To"])
        log.append((self.state.info["Tu"],self.state.info["To"]))
        
        if(self.task_queue.qsize()>=self.state.info["To"]):
            self.state.info["state"]=2
        elif(self.task_queue.qsize()<=self.state.info["Tu"]):
            self.state.info["state"] =0
        else:
            self.state.info["state"] =1
        #self.lock.release()
        ip_id = self.IP_FIND()
        for ip, id in ip_id.items():
            packet = stat_packet(id=self.state.info["id"], To=self.state.info["To"],
                                 Tu=self.state.info["Tu"], state=self.state.info["state"])
            self.send(packet, ip)
        self.lock.release()
        self.update_flag=0
        threading.Timer(10, self.update_state).start()
        #threading.Thread(target=self.time_monitor).start()
        
    def time_monitor(self):
        self.time_dict.clear()
        timer_thread1 = threading.Thread(target=self.time_calcu,args=(0,))
        timer_thread2 = threading.Thread(target=self.time_calcu,args=(1,))
        timer_thread3 = threading.Thread(target=self.time_calcu,args=(2,))
        
        timer_thread1.start()
        timer_thread2.start()
        timer_thread3.start()

    def time_calcu(self,monitor_state):
        self.local.sum_=0
        while True:
            if(self.state.info["state"] == monitor_state):
                time1=time.time()
                while(self.state.info["state"] == monitor_state):
                    time.sleep(0.1)
                    if(self.update_flag==1):
                        break
                time2=time.time()
                self.local.sum_+=time2-time1

            if(self.update_flag==1):
                self.time_dict[monitor_state]=self.local.sum_
                break
        





















if __name__ == "__main__":

    ipfs_api = "/ip4/127.0.0.1/tcp/5001"
    node = node(ipfs_api,3)
    node.key_create()
    
    t=threading.Thread(target=node.receive)
    t.start()
    #init neighbor state
    time.sleep(30)
    ip_id=node.IP_FIND()
    print(ip_id)
    for ip,id in ip_id.items():
        node.send(node.state,ip)
    while(len(node.neighbor_state)<len(ip_id)):
        pass


    #print(neighbor_state)
    for i in range(1):
        t=threading.Thread(target=node.worker)

        t.start()
    
    #threading.Timer(10,node.update_state).start()
        
    #threading.Thread(target=node.time_monitor).start()
    with open("hash_file.txt") as  f:
        hash_CIDs=f.readlines()
        node.time_stat1=time.time()
        shuffle(hash_CIDs)
        for i in range(2):
            for hash_CID in hash_CIDs:
                if(len(hash_CID.strip())!=0):
                    CID=hash_CID.strip().split(":")[0]
                    ip=hash_CID.strip().split(":")[1]
                    if(ip!=node.IP):
                        request=info_packet(CID=CID,IP=node.IP,check=0)
                        node.send(request,ip)
                        time.sleep(0.1)
    #node.file_encrypt_and_upload("test.txt")

    #print(node.record)
    #node.self_decrypt(list(node.record.keys())[-1])
    #print(node.state.info)
   

















