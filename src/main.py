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

#-----Global variables-----------------------------------------------------
netsocket = None
peerDic = {}
myNodeNum = 0
firstNodeStatus = ''  # "WaitForPeers"  "StopAcceptingPeers" "StartComputing"
#---parameters
n_hbc = 0 # n>2 number of hbc
c_collude = 2 # c<n, dishonesty colluding peers
k_set_size = 5 # set size
s_set = list() #local set
# sk, pk



#--------stepOne-----------------------------------------------------
def stepOne():
    # calculate polynomial fi
    fi = np.poly1d(s_set,True).c
    print "fi:",fi
    # encrypt fi
    
    # send encrypt fi to i+1 ... i+c
    
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
    msgDic = {'PeerList':peerDic,
              'OriginNum':1}
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
    
    # update my address at 0
    # update peer dic
    if msgdict['OriginNum']!=1:
        return
    newPeerDic = msgdict['PeerList']
    for num, addr in newPeerDic.items():
        if int(num) != 0 and int(num) != 1:
            peerDic[int(num)]=(str(addr[0]),addr[1])
    print myNodeNum
    myaddr = newPeerDic[str(myNodeNum)]
    peerDic[0]=(str(myaddr[0]),myaddr[1])
    print "UpdatedPeerList"
    print peerDic
#--------processPendingMsg-----------------------------------------------------    
def processPendingMsg(rawmsg, origin_addr):
    print "recieved from address", origin_addr
    msgdict = json.loads(str(rawmsg))  # @@@ json to dictionary
    
    if 'Join' in msgdict:
        processJoinMsg(origin_addr)
    if 'NodeNum' in msgdict and 'OriginNum' in msgdict:
        processRplyNodeNumMsg(msgdict)
    if 'PeerList' in msgdict and 'OriginNum' in msgdict:
        processPeerListMsg(msgdict)
        
   
#--------broadcastPeerList-----------------------------------------------------
def broadcastPeerList():
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
                    broadcastPeerList()
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
    stepOne()
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