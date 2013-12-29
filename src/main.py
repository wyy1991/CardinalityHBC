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

#-----Global variables-----------------------------------------------------
netsocket = None
peerDic = {}
myNodeNum = 0

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
#--------processJoinMsg-----------------------------------------------------
def processJoinMsg(origin_addr):
    global peerDic
    originInList = False
    for number, address in peerDic.items() :
        if address == origin_addr:
            originInList = True
    if originInList == False:
        # insert origin into peerDict
        newNodeNum =len(peerDic)
        peerDic[newNodeNum] = [origin_addr[0], origin_addr[1]]
        print "Insert peer No.", newNodeNum
        rplyNodeNumMsg = createRplyNodeNumMsg(newNodeNum)
        netsocket.sendto(rplyNodeNumMsg, origin_addr)


#--------processRplyNodeNumMsg-----------------------------------------------------
def processRplyNodeNumMsg(msgdict):
    global myNodeNum
    global peerDic
    # set my node number 
    if 0==myNodeNum and 1==int(msgdict['OriginNum']):
        myNodeNum = int(msgdict['NodeNum'])
        #insert into peerdic
        peerDic[myNodeNum] = peerDic[0]
        print "My node num is :", myNodeNum

        
#--------processPendingMsg-----------------------------------------------------    
def processPendingMsg(rawmsg, origin_addr):
    print "recieved from address", origin_addr
    msgdict = json.loads(str(rawmsg))  # @@@ json to dictionary
    
    if 'Join' in msgdict and 1 == myNodeNum:
        processJoinMsg(origin_addr)
    if 'NodeNum' in msgdict and 'OriginNum' in msgdict:
        processRplyNodeNumMsg(msgdict)
        
   
#--------the big loop-----------------------------------------------------
def mainLoop():
    global netsocket
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
                    print peerDic
                    
                except socket.error, (code,message):
                    print "Error: socket broken: " + message
                    running = False
    
            elif s == sys.stdin:
                # handle standard input
                textin = sys.stdin.readline()
                
                if textin == "q\n":
                    running = False
                elif textin == "s\n":
                    #@@@ to do start computing
                    next = 0 #@@@ to do
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
    
    iamNodeOne = isFirstNode()
   
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
        peerDic[1] = (myip, myport)
    else:
        enterFirstNodeAddr()
        print peerDic
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