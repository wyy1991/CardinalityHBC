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
fi_enc_dic = {} # dictionary of <node num, list of fi_enc's coeff[]>
r_set = {} # <nodeNum, list of r's coeff[]> 
theta = []
lambda_my = []
reply_check_theta_list = []
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
    try:
        return paillier.encrypt(pub, plain)
    except:
        return 0
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
def homo_encrypt_poly(pub, f):
    # encrypt a f[]
    f_enc = []
    for val in range(0,len(f)):
        f_enc.append(homo_encrypt(pub,f[val]))
    return f_enc
def homo_add_poly(f1, f2):
    # return E(g[i]) = E(f1) + E(f2)
    g = []
    degf1 = len(f1)-1
    degf2 = len(f2)-1
    deg_g = 0
    if degf1 == degf2:
        for i in range(0,degf1+1):
            g.append(0)
        deg_g = len(g)-1
        for i in range(0,degf1+1):
            g[i]= homo_add(pk, f1[i], f2[i])
    if degf1 > degf2:
        for i in range(0,degf1+1):
            g.append(0)
        deg_g = len(g)-1
        for i in range(0,degf2+1):
            g[deg_g-i]=homo_add(pk,f1[degf1-i],f2[degf2-i])
        for i in range(degf2+1,degf1+1):
            g[deg_g-i]=f1[degf1-i]
    if degf1 < degf2:
        for i in range(0,degf2+1):
            g.append(0)
        deg_g = len(g)-1
        for i in range(0,degf1+1):
            g[deg_g-i]=homo_add(pk,f1[degf1-i],f2[degf2-i])
        for i in range(degf1+1,degf2+1):
            g[deg_g-i]=f2[degf2-i]
    return g
def homo_mult_poly(pub, f1_enc, f2):
    g=[]
    deg_f1 = len(f1_enc)-1
    deg_f2 = len(f2)-1
    deg_g = deg_f1 + deg_f2 
    for gi in range(0,deg_g+1):
        g.append(0)
    for bigi in range(0,deg_g+1):
        for i in range(0, bigi+1):
            if deg_f1-(bigi-i) < 0 or deg_f2-i < 0:
                e_mult = 0
            else:
                e_mult = homo_mult(pub, f1_enc[deg_f1-(bigi-i)], f2[deg_f2-i])
            if 0==g[deg_g - bigi]:
                g[deg_g - bigi] = e_mult
            elif 0!=e_mult:
                g[deg_g - bigi] = homo_add(pub, g[deg_g - bigi], e_mult)
    return g


def homo_evalutate(pub, f1_enc, b):
    # return E(a) = fi_enc plug in b
    a_enc = 0
    deg_f1 = len(f1_enc)-1
    for k in range (0, deg_f1+1):
        bpower = b**k
        tmp = homo_mult(pk, f1_enc[deg_f1 - k], bpower)
        if a_enc == 0:
            a_enc = tmp
        else:
            a_enc = homo_add(pub, a_enc, tmp)
    return a_enc
#--------broadcastPeerList-----------------------------------------------------
def generateKeyPair():    
    global sk
    global pk
    if myNodeNum == 1:
        priv, pub = homo_generateKeyPair(128)
        sk = priv
        pk = pub
        
#--------stepOne_ab-----------------------------------------------------
def stepOne_ab():
    global fi_enc_dic
    # calculate polynomial fi
    fi = np.poly1d(s_set,True).c
    print "fi:",fi
    # encrypt fi
    fi_enc = homo_encrypt_poly(pk, fi)
    fi_enc_dic[myNodeNum]= fi_enc   # store into fi_enc_dic
    #print "fi_enc:", fi_enc
    # create new message fi
    
    # send encrypt fi to i+1 ... i+c
    print "send fi_enc to "
    print "n_hbc=",n_hbc
    for tar in range(1,c_collude+1):
        tar_num = myNodeNum + tar
        if tar_num > n_hbc:
            tar_num = tar_num - n_hbc 
        print tar_num
        fi_msg = createFiMsg(fi_enc, tar_num)
        netsocket.sendto(fi_msg, peerDic[tar_num])
        
        
#--------stepOne_cd-----------------------------------------------------
def stepOne_cd():
    global r_set
    global fi_enc_dic
    global theta
    print "Start step 1cd."
    # choose c+1 random poly 0 ... c with degree k
    degree = k_set_size
    r = []
    # for num from received
    #print "fi_enc_dic = ", fi_enc_dic.keys()
    for num in fi_enc_dic.keys():
        r = []
        for d in range(0,degree+1):
            r.append((int(time.time()*1000) + randint(0,10))%100)
        r_set[num] = r
    print "r_set = ",r_set
    
    # calculate encryption of  theta i
    theta_coef = []
    for index in fi_enc_dic.keys():
        f_tmp = fi_enc_dic[index]
        r_tmp = r_set[index]
        #@@@ now 
        fxr_tmp = homo_mult_poly(pk,f_tmp, r_tmp)
        theta_coef = homo_add_poly(fxr_tmp, theta_coef)
    theta = theta_coef
    #print "theta = ", theta
    print "calculated my theta"
    # send to node one,for done step 1cd
    rplyMsg = createRplyMsg('Rply_theta_created', 1)
    netsocket.sendto(rplyMsg, peerDic[1])    
    
        
#--------stepTwo-----------------------------------------------------
def stepTwo():
    global lambda_my
    # only for step number 
    if myNodeNum != 1:
        print 'step two only for node one.'
        return 
    print "Start step two."
    # lambda = encrypted theta  
    #lambda_my = homo_encrypt_poly(pk, theta)
    lambda_my = theta
    # send lambda
    lambdaMsg = createPolyMsg(lambda_my,'Lambda', myNodeNum+1)
    netsocket.sendto(lambdaMsg, peerDic[myNodeNum+1]) # should send to node 2
    print "Send lambda 1 to node", myNodeNum+1



#--------stepFive_ab-----------------------------------------------------
def stepFive_ab(lambda_n):
    # evaluate encryption to get E(cij) = p((Si)j)
    print "[Step 5 ab]"
    #print "lambda_n:",lambda_n
    print "s_set:",s_set
    print "fi_enc_dic:", fi_enc_dic
    cij_list = []
    vij_list = []
    vij_dec_list = []
    for j in range(0, k_set_size):
        cij_list.append(0)
        vij_list.append(0)
        vij_dec_list.append(0)
    for j in range(0, k_set_size):
        cij_list[j]= homo_evalutate(pk, lambda_n, s_set[j])
    
    #print 'cij_list:', cij_list
    
    # for j = 1 to k, choose rij <- R, 
    # evaluate (Vi)j = rijxh E(cij)
    
    for j in range (0, k_set_size):
        r_rand=num = randint(0,100)
        vij_list[j] = homo_mult(pk, cij_list[j], r_rand)
    print 'vij_list:',vij_list
    
    for j in range (0, k_set_size):
        '''for test'''
        vij_dec_list[j] = homo_decrypt(sk, pk, vij_list[j])
        
    print "vij_dec_list:", vij_dec_list
    
    #send reply to node 1
    rply_vset_msg = createRplyMsg('Got_Vset', 1)
    netsocket.sendto(rply_vset_msg,peerDic[1])
    print 'Send vset reply msg to node 1'
    
#--------startShuffle----------------------------------------------------
def startShuffle():
    # todo
    return 0
    
#--------initLocalSet-----------------------------------------------------
def initLocalSet():
    global s_set
    for i in range(0,k_set_size):
        num = (int(time.time()*1000) + randint(0,10))%10
        s_set.append(num)
    print "s_set:",s_set
    
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

#--------createPolyMsg-----------------------------------------------------
def createPolyMsg(f,polytype, targetNum):
    msgDic = {'PolyType':polytype,
              'Poly':f,
              'OriginNum':myNodeNum,
              'TargetNum':targetNum}
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
    global n_hbc
    
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
    n_hbc = len(peerDic) - 1
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
                reply_check_plist = []
                commandMsg = createCommandMsg('Start_Step_1ab',myNodeNum,tar)
                netsocket.sendto(commandMsg,peerDic[tar])
            #@@@ Node 1 can start Step 1b
            
    
    # when first node receives all reply from all nodes about theta created 
    if replyText == 'Rply_theta_created' and myNodeNum == 1:
        reply_check_plist.append(originNum)
        if len(reply_check_plist) == n_hbc-1:
            print "All nodes computed theta."
            reply_check_plist = []
            # node one start step two 
            stepTwo()
    if replyText == 'Got_Vset' and myNodeNum == 1:
        reply_check_plist.append(originNum)
        if len(reply_check_plist) == n_hbc + 1:
            print "All nodes computed V set. Next shuffle."
            reply_check_plist = []
            startShuffle()
        

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
    global fi_enc_dic
    fi_enc = msgdict['Fi_enc']
    originNum = msgdict['OriginNum']
    targetNum = msgdict['TargetNum']
    fi_enc_dic[originNum] = fi_enc
    print "got fi from ", originNum
    #check if received enough to go to next step
    if len(fi_enc_dic) >= c_collude+1:  # add the one from self
        stepOne_cd()

#--------processPolyMsg-----------------------------------------------------         
def processPolyMsg(msgdict):
    global lambda_my
    # process 
    poly = msgdict['Poly']
    polytype = msgdict['PolyType']
    originNum = msgdict['OriginNum']
    targetNum = msgdict['TargetNum']
    
    if targetNum != myNodeNum:
        return 
    if polytype == 'Lambda' and targetNum == myNodeNum and originNum == myNodeNum-1 and myNodeNum != 1:
        lambda_other = poly
        #lambda = lambda other + theta  (encrypted)
        lambda_my = homo_add_poly(lambda_other, theta)
        #send the encryption to  player i+1 mod n
        print "myNodeNum = ",myNodeNum,"n_hbc = ",n_hbc 
        tar = (myNodeNum + 1)
        if tar > n_hbc:
            tar = tar - n_hbc
        theta_out_msg =  createPolyMsg(lambda_my,'Lambda', tar)
        print "Send theta out to node ",tar
        netsocket.sendto(theta_out_msg, peerDic[tar])
        print "theta_out_msg send!"
    elif polytype == 'Lambda' and targetNum == myNodeNum and myNodeNum == 1:
        #when node 1 receives lambda n, it sends out to all other players
        lambda_n = poly
        print "Send lambda N to all peers."
        for tar in range(1, n_hbc+1):
            lambda_n_out_msg = createPolyMsg(lambda_n , 'Lambda_N', tar)
            netsocket.sendto(lambda_n_out_msg, peerDic[tar])
    elif polytype == 'Lambda_N' and originNum == 1:
        print "Got Lambda_N"
        # step 5
        stepFive_ab(poly)
    else:
        return 
        
#--------processPendingMsg-----------------------------------------------------    
def processPendingMsg(rawmsg, origin_addr):
    print "received from address", origin_addr
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
    if 'PolyType' in msgdict and 'Poly' in msgdict and 'OriginNum' in msgdict and 'TargetNum' in msgdict:
        processPolyMsg(msgdict)
    
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
                    #print "received" + data
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
                    #@@@ testcode
                    '''
                    print "------test--------"
                         
                    test_list2 =   [  125,  684, 1]
                    print "test list2:", test_list2
                    for test_index in range(0, len(test_list2)):
                        try:
                            enc = homo_encrypt(pk, int(test_list2[test_index]))
                            print test_list2[test_index], ":",enc, ":",homo_decrypt(sk, pk,enc)
                        except:
                            print "error"
                    
                    test_list1= np.poly1d([2,1,3,6,3],True).c
                    print "test list1:", test_list1
                    for test_index in range(0, len(test_list1)):
                        # create socket
                        try:
                            enc = homo_encrypt(pk, int(test_list1[test_index]))
                            print test_list1[test_index], ":", enc, ":",homo_decrypt(sk, pk,enc)
                   
                        #print newsocket.getsockname()
                        except:
                            print "error"
                    print "homo_enc_poly:",homo_encrypt_poly(pk, test_list1)
                    '''
                    
                    '''
                    sum = homo_add_poly([homo_encrypt(pk,4),homo_encrypt(pk,3),homo_encrypt(pk,2),homo_encrypt(pk,1)], [homo_encrypt(pk,2),homo_encrypt(pk,1)])
                    print "sum = "
                    for p in sum:
                        print homo_decrypt(sk, pk,p )
                    
                    print homo_decrypt(sk, pk,homo_add(pk, 0,homo_encrypt(pk,2)))
                    print 'E(2)x3=', homo_mult(pk, homo_encrypt(pk,3), 2)
                    print homo_decrypt(sk, pk,  homo_mult(pk, homo_encrypt(pk,1), -2))
                    polya = np.poly1d([3,2,1])
                    polyb = np.poly1d([3,2,1])
                    print np.polymul(polya, polyb)
                    
                    ppoly = homo_mult_poly(pk, [homo_encrypt(pk,3),homo_encrypt(pk,2),homo_encrypt(pk,1)], [3,2,1])
                    for p in ppoly:
                        print homo_decrypt(sk, pk,p )
                        '''
                    '''
                    print "----------------"
                    '''
                    
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