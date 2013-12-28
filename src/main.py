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

#--------create socket-----------------------------------------------------
def createSocket():
    newsocket = None
    host = ''
    port = 50000 + randint(1,1000)

    
    # create socket
    try:
        newsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        newsocket.bind((host,port))
        #print newsocket.getsockname()
    except socket.error, (code,message):
        if newsocket:
            newsocket.close()
        print "Could not open socket: " + message
        sys.exit(1)
        
    return newsocket
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
def enterFirstNodeAddr(peerDic):
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
            peerDic[1] = [addrInList[0], int(addrInList[1])] 
            # insert the address to peerlist
            waitForFirstNode = False
    return peerDic
#--------create message-----------------------------------------------------
def createConnectFirstNodeMsg(originIP, originPort):
    msgDic = {'Origin':[originIP, originPort],
              'Join':1}
    msgStr=json.dumps(msgDic)
    return msgStr

def processJoinMsg(origin_addr, peerDict):
    originInList = False
    for number, address in peerDict.items() :
        if address == origin_addr:
            originInList = True
    if originInList == False:
        # insert origin into peerDict
        peerDict[len(peerDict)] = [origin_addr[0], origin_addr[1]]
        print "Insert peer."
    return peerDict
    
    

def processPendingMsg(rawmsg, origin_addr, peerDict):
    print "recieved from address", origin_addr
    msgdict = json.loads(str(rawmsg))  # @@@ json to dictionary
    
    if 'Join' in msgdict:
        peerDict = processJoinMsg(origin_addr, peerDict)
    
    #check if exist
    return peerDict

#--------main function-----------------------------------------------------
def main():
    iamNodeOne = isFirstNode()
    size = 1024
    # create socket
    netsocket = createSocket()
    myip = getPublicIp()
    myport = netsocket.getsockname()[1] 
    print "Address:", myip, ":", myport
    
    # <peer number, address>
    peerDic ={ 0 : [myip, myport] } # key 0, stores my address
    myNodeNum = 0;
    if iamNodeOne:
        myNodeNum = 1
        peerDic[1] = [myip, myport]
    else:
        peerDic = enterFirstNodeAddr(peerDic)
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
    
    # loop through sockets
    input = [netsocket,sys.stdin]
    running = True
    
    while running:
        inputready,outputready,exceptready = select.select(input,[],[])
        
        for s in inputready:
    
            if s == netsocket:
                # handle the netsocket socket
                try:
                    data,address = netsocket.recvfrom(size)
                    print "received" + data
                    # got pending msg
                    peerDic = processPendingMsg(data, address, peerDic)
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
#-------main------------------------------------------------------
if __name__ == '__main__':
    main()