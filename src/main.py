#!/usr/bin/python python
# -*- coding: utf-8 -*-

import select
import socket
import random
import sys
import json
import re
from urllib import urlopen
from random import randint
import time
import math
import numpy as np
import paillier



#-----Global variables-----------------------------------------------------
netsocket = None
peerDic = {}
myNodeNum = 0
firstNodeStatus = ''  # "WaitForPeers"  "StopAcceptingPeers" "StartComputing"
reply_check_plist = []
#---parameters
n_hbc = 0 # n>2 number of hbc
c_collude = 2 # c<n, dishonesty colluding peers
k_set_size = 5 # set size
s_set = list() #local set
sk = None # private key
pk = None # public key


#--------Homo crypto-----------------------------------------------------
def homo_generateKeyPair(numOfBits):
    priv, pub = paillier.generate_keypair(numOfBits)
    return priv, pub
def homo_encrypt(pub,plain):
    return paillier.encrypt(pub, plain)
def homo_decrypt(priv, pub, cipher):
    return paillier.decrypt(priv, pub, cipher)
def homo_add(pub, cipher_a, cipher_b):
    #returns E(m1 + m2) given E(m1) and E(m2).
    return paillier.e_add(pub, cipher_a, cipher_b)
def homo_mult(pub, ciphertext, n):
    #Returns E(a*m) given E(m), a
    return paillier.e_mul_const(pub, ciphertext, n)
def homo_affine(pub, ciphertext, a, b):
    #Returns E(a*m + b) given E(m), a and b.
    a_mult_ciphertext = pow(ciphertext, a, pub.n_sq)
    return a_mult_ciphertext * pow(pub.g, b, pub.n_sq) % pub.n_sq


#--------broadcastPeerList-----------------------------------------------------
def generateKeyPair():    
    global sk
    global pk
    if myNodeNum == 1:
        priv, pub = homo_generateKeyPair(64)
        sk = priv
        pk = pub
        
#--------stepOne_ab-----------------------------------------------------
def stepOne_ab():
    # calculate polynomial fi
    fi = np.poly1d(s_set,True).c
    print "fi:",fi
    # encrypt fi
    fi_enc = []
    for val in fi:
        fi_enc.append(homo_encrypt(pk,val))
    print "fi_enc:", fi_enc
    # create new message fi
    
    # send encrypt fi to i+1 ... i+c
    print "send fi_enc to ",myNodeNum+1," to ", myNodeNum+c_collude+1
    for tar in range(1,c_collude+1):
        tar_num = myNodeNum + tar
        fi_msg = createFiMsg(fi_enc, tar_num)
        netsocket.sendto(fi_msg, peerDic[tar_num])
        
        
#--------stepOne_cd-----------------------------------------------------
def stepOne_cd():
    # choose c+1 random poly 0 ... c with degree k
    
    # seems need to accept from other peers
    
    # calculate encryption of  theta i
    
    return 0
    
    
#--------initLocalSet-----------------------------------------------------
def initLocalSet():
    global s_set
    for i in range(0,k_set_size):
        num = (int(time.time()*1000) + randint(0,10))%10
        s_set.append(num)
    print s_set
    
#--------create socket-----------------------------------------------------
def createSocket():
    global netsocket
    host = ''
    port = 50000 + randint(1,1000)

    
    # create socket
    try:
        netsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netsocket.bind((host,port))
        #print newsocket.getsockname()
    except socket.error, (code,message):
        if netsocket:
            netsocket.close()
        print "Could not open socket: " + message
        sys.exit(1)
        
#--------getPublicIP-----------------------------------------------------
def getPublicIp():
    data = str(urlopen('http://checkip.dyndns.com/').read())  #@@@ my have problem
    # data = '<html><head><title>Current IP Check</title></head><body>Current IP Address: 65.96.168.198</body></html>\r\n'

    return re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)
#--------isFirstNode-----------------------------------------------------
def isFirstNode():
    if len(sys.argv) <= 1:
        return False
    elif sys.argv[1] == "first":
        print "This is node One!"
        return True
#--------enterFirstNodeAddr-----------------------------------------------------
def enterFirstNodeAddr():
    global peerDic
    # ask for node one address
    waitForFirstNode = True
    while waitForFirstNode:
        print "Please enter address of node one, x.x.x.x:xxxx"
        sys.stdout.write("%")
        addrIn = sys.stdin.readline()
        addrInList = addrIn.rstrip('\n').split(":")
        # check if input valid
        if 2 != len(addrInList):
            print "Invalid address!"
        elif 4 != len(addrInList[0].split(".")):
            print "Invalid ip!"
        else:
            peerDic[1] = (addrInList[0], int(addrInList[1])) 
            # insert the address to peerlist
            waitForFirstNode = False
#--------createConnectFirstNodeMsg-----------------------------------------------------
def createConnectFirstNodeMsg(originIP, originPort):
    msgDic = {'Origin':[originIP, originPort],
              'Join':1}
    msgStr=json.dumps(msgDic)
    return msgStr

#--------createConnectFirstNodeMsg-----------------------------------------------------
def createRplyNodeNumMsg(n):
    msgDic = {'NodeNum':n,
              'OriginNum':1}
    msgStr=json.dumps(msgDic)
    return msgStr


#--------createPeerListMsg-----------------------------------------------------
def createPeerListMsg():
    skey = [sk.l, sk.m]
    pkey = [pk.n, pk.n_sq, pk.g]
    
    msgDic = {'PeerList':peerDic,
              'SKey':skey,
              'PKey':pkey,
              'OriginNum':1}
    msgStr=json.dumps(msgDic)
    return msgStr

#--------createRplyMsg(replyText)-----------------------------------------------------
def createRplyMsg(replyText, targetNum):
    msgDic = {'Reply':replyText,
              'TargetNum':targetNum,
              'OriginNum':myNodeNum}
    msgStr=json.dumps(msgDic)
    return msgStr

#--------createFiyMsg(replyText)-----------------------------------------------------
def createFiMsg(fi_enc, target):
    msgDic = {'Fi_enc':fi_enc,
              'TargetNum':target,
              'OriginNum':myNodeNum}
    msgStr=json.dumps(msgDic)
    return msgStr


#--------createCommandMsg-----------------------------------------------------
def createCommandMsg(command,origin,target):
    msgDic = {'Command':command,
              'TargetNum':target,
              'OriginNum':origin}
    msgStr=json.dumps(msgDic)
    return msgStr

#--------processJoinMsg-----------------------------------------------------
def processJoinMsg(origin_addr):
    global peerDic 
    global myNodeNum
    if 1 != myNodeNum or firstNodeStatus !="WaitForPeers":
        print "Not accepting new peers now!"
        return
    
    originInList = False
    for number, address in peerDic.items() :
        if address == origin_addr:
            originInList = True
    if originInList == False:
        # insert origin into peerDict
        newNodeNum =len(peerDic)
        peerDic[newNodeNum] = (origin_addr[0], origin_addr[1])
        print "Insert peer No.", newNodeNum
        rplyNodeNumMsg = createRplyNodeNumMsg(newNodeNum)
        netsocket.sendto(rplyNodeNumMsg, origin_addr)


#--------processRplyNodeNumMsg-----------------------------------------------------
def processRplyNodeNumMsg(msgdict):
    global myNodeNum
    global peerDic
    if 1 == myNodeNum:
        return
    # set my node number 
    if 0==myNodeNum and 1==int(msgdict['OriginNum']):
        myNodeNum = int(msgdict['NodeNum'])
        #insert into peerdic
        peerDic[myNodeNum] = peerDic[0]
        print "My node num is :", myNodeNum

#--------processPeerListMsg-----------------------------------------------------  
def processPeerListMsg(msgdict):
    global peerDic
    global myNodeNum
    global sk
    global pk
    
    # update my address at 0
    # update peer dic
    if myNodeNum == 1:
        return
    if msgdict['OriginNum']!=1:
        return
    skey = msgdict['SKey']
    pkey = msgdict['PKey']
    
    sk = paillier.PrivateKey()
    pk = paillier.PublicKey()
    sk.l = skey[0]
    sk.m = skey[1]
    pk.n = pkey[0]
    pk.n_sq = pkey[1]
    pk.g = pkey[2] 
    print "Updated sk pk"
    newPeerDic = msgdict['PeerList']
    for num, addr in newPeerDic.items():
        if int(num) != 0 and int(num) != 1:
            peerDic[int(num)]=(str(addr[0]),addr[1])
    print "MyNodeNum=",myNodeNum
    myaddr = newPeerDic[str(myNodeNum)]
    peerDic[0]=(str(myaddr[0]),myaddr[1])
    print "UpdatedPeerList"
    print peerDic
    
    #send reply to node one
    pListRplyMsg = createRplyMsg('Received_PList_Keys',1)
    netsocket.sendto(pListRplyMsg,peerDic[1])
    print "send pListRplyMsg"
#--------processReplyMsg-----------only first node------------------------------------------
def processReplyMsg(msgdict, origin_addr):
    global reply_check_plist
    
    originNum = msgdict['OriginNum']
    replyText = msgdict['Reply']
    targetNum = msgdict['TargetNum']
    #only target node receives the msg
    if targetNum!=myNodeNum:
        return
    if replyText == 'Received_PList_Keys':
        reply_check_plist.append(originNum)
        if len(reply_check_plist) == n_hbc-1:
            print "All nodes received plist and keys."
            #send out command for Step 1ab to all peer including me
            for tar in range(1,n_hbc+1):
                commandMsg = createCommandMsg('Start_Step_1ab',myNodeNum,tar)
                netsocket.sendto(commandMsg,peerDic[tar])
            #@@@ Node 1 can start Step 1b
            

#--------processCommandMsg-----------------------------------------------------
def processCommandMsg(msgdict):
    commandText = msgdict['Command']
    originNum = msgdict['OriginNum']
    targetNum = msgdict['TargetNum']
    
    if originNum==1 and targetNum == myNodeNum and commandText=='Start_Step_1ab':
        print "received command start_Step_1ab"
        # start step 1ab
        stepOne_ab()
        
#--------processFiEncMsg-----------------------------------------------------   
def processFiEncMsg(msgdict):
    stepOne_cd()
#--------processPendingMsg-----------------------------------------------------    
def processPendingMsg(rawmsg, origin_addr):
    print "recieved from address", origin_addr
    msgdict = json.loads(str(rawmsg))  # @@@ json to dictionary
    
    if 'Join' in msgdict:
        processJoinMsg(origin_addr)
    if 'NodeNum' in msgdict and 'OriginNum' in msgdict:
        processRplyNodeNumMsg(msgdict)
    if 'PeerList' in msgdict and 'OriginNum' in msgdict and 'SKey' in msgdict and'PKey' in msgdict:
        processPeerListMsg(msgdict)
    if 'TargetNum' in msgdict and 'OriginNum' in msgdict and 'Reply' in msgdict:
        processReplyMsg(msgdict, origin_addr)
    if 'Command' in msgdict and 'TargetNum' in msgdict and 'OriginNum' in msgdict:
        processCommandMsg(msgdict)
    if 'Fi_enc' in msgdict and 'TargetNum' in msgdict and 'OriginNum' in msgdict:
        processFiEncMsg(msgdict)
    
#--------broadcastPeerList-----------------------------------------------------
def broadcastPeerListandKeys():
    print "broadcast peer list"
    print peerDic
    # send message to all peers
    pListMsg = createPeerListMsg()
    for number, address in peerDic.items() :
        if number != 0 and number != myNodeNum:
            netsocket.sendto(pListMsg,address)

#--------the big loop-----------------------------------------------------
def mainLoop():
    global netsocket
    global firstNodeStatus
    global n_hbc
    # loop through sockets
    input = [netsocket,sys.stdin]
    running = True
    size = 1024
    print "waiting in main loop..."
    while running:
        inputready,outputready,exceptready = select.select(input,[],[])
        
        for s in inputready:
    
            if s == netsocket:
                # handle the netsocket socket
                try:
                    data,address = netsocket.recvfrom(size)
                    print "received" + data
                    # got pending msg
                    processPendingMsg(data, address)
                    
                    
                except socket.error, (code,message):
                    print "Error: socket broken: " + message
                    running = False
    
            elif s == sys.stdin:
                # handle standard input
                textin = sys.stdin.readline()
                
                if textin == "q\n":
                    running = False
                elif textin == "s\n" and myNodeNum == 1:
                    #@@@ to do start computing
                    firstNodeStatus = "StopAcceptingPeers"
                    print "Stop accepting new peers."
                    n_hbc = len(peerDic) - 1
                    generateKeyPair()
                    print "sk=",sk,"pk=",pk
                    broadcastPeerListandKeys()

                else:
                    #netsocket.sendto(textin,(host,port)) 
                    running = True
                
    # close netsocket socket
    netsocket.close()
    sys.stdout.write("netsocket closed.")
#--------main function-----------------------------------------------------
def main():
    global netsocket
    global peerDic
    global myNodeNum
    global firstNodeStatus 
    
    iamNodeOne = isFirstNode()
    # local computation
    initLocalSet()
    # create socket
    createSocket()
    #myip = getPublicIp()
    myip = netsocket.getsockname()[0] 
    myport = netsocket.getsockname()[1] 
    print "Address:", myip, ":", myport
    
    # <peer number, address>
    peerDic[0] = (myip, myport) # key 0, stores my address
    myNodeNum = 0;
    if iamNodeOne:
        myNodeNum = 1
        firstNodeStatus = "WaitForPeers"
        peerDic[1] = (myip, myport)
    else:
        enterFirstNodeAddr()
        print "First node set."
        # create message
        joinmsg = createConnectFirstNodeMsg(myip, myport)
        # send message to first node
        netsocket.sendto(joinmsg,(peerDic[1][0], peerDic[1][1]))
        
    # if not, ask for input of node one address
    # connect to node one, and get node number back
    
    if iamNodeOne:
        print "Waiting for other nodes to join..."
        print "Enter s to stop waiting and start. Enter q to quit."
    
    mainLoop()
  
#-------main------------------------------------------------------
if __name__ == '__main__':
    main()