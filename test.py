'''import ipfshttpclient
client=ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5002")
a=b"hkkkkk 8"
res=client.add_bytes(a)
print(res)
k=client.cat(res).split()

print(k[0])
print(k[1])
from collections import defaultdict
def match(pattern, str_test):
    if (str_test == None or pattern == None): return False
    dict_=defaultdict(str)
    reverse_dict=defaultdict(str)
    str_list = str_test.split()
    if (len(str_list) != len(pattern)): return False
    flag=0
    for str_ in str_list:


        if (str_ not in dict_):
            dict_[str_] = pattern[flag]
            if(pattern[flag] not in reverse_dict):
                reverse_dict[pattern[flag]]=str_
            else:
                return False
            flag+=1

        else:
            if dict_[str_] != pattern[flag]:
                return False
            else:
                flag += 1
    print(flag)

    return True
print(match(pattern=None,str_test="yuuu"))'''
'''from umbral import pre, keys, signing, config, params, kfrags, cfrags
config.set_default_curve()
pri_key=keys.UmbralPrivateKey.gen_key()
pub_key=pri_key.get_pubkey()
plaintext="你快看看"
encryption_message,capsule=pre.encrypt(pub_key,plaintext.encode("utf-8"))
k=pre.decrypt(encryption_message,capsule,pri_key)
print(k.decode("utf-8"))'''















