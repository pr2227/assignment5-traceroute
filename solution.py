from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    # Make a basic header with a 0 checksum
    myChecksum = 0

    # struct -- Interpret strings as packed binary data
    myID = os.getpid() & 0xFFFF  # Return the current process i
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist2 = [] #This is your list to contain all traces
    destAddr = gethostbyname(hostname) # Moved destAddr out of for loop to ensure the hostname is only looked up once

    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            tracelist1 = [] #This is your list to use when iterating through each trace 
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                
                # Record timeouts and record the hop
                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append(tracelist1)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append(tracelist1)
            except timeout:
                continue

            else:
                # Fetch the icmp type from the IP packet
                types, code, checksum, identifier, sequenceNum = struct.unpack("bbHHh",recvPacket[20:28])
                try: # Fetch the hostname
                    hostAddr = gethostbyaddr(addr[0])[0]
                
                except herror:   #if the host does not provide a hostname
                    hostAddr = 'hostname not returnable'
                
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    RTT = str(round((timeReceived - timeSent), 2))
                    tracelist1.append(str(ttl))
                    tracelist1.append(RTT)
                    tracelist1.append(addr[0])
                    tracelist1.append(hostAddr)
                    tracelist2.append(tracelist1)

                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    RTT = str(round((timeReceived - timeSent), 2))
                    tracelist1.append(str(ttl))
                    tracelist1.append(RTT)
                    tracelist1.append(addr[0])
                    tracelist1.append(hostAddr)
                    tracelist2.append(tracelist1)

                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    RTT = str(round((timeReceived - timeSent), 2))
                    tracelist1.append(str(ttl))
                    tracelist1.append(RTT)
                    tracelist1.append(addr[0])
                    tracelist1.append(hostAddr)
                    tracelist2.append(tracelist1)
                    return tracelist2
                
                else:
                    tracelist2.append('Error')
                break

            finally:
                mySocket.close()

if __name__ == '__main__':
    get_route("google.co.il")