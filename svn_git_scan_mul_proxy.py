#!/usr/bin/env python 
# -*- encoding: utf-8 -*- 

# 
# Note that you have to run the script in the same version of python which 
# was used to generate the exe. Otherwise unmarshalling will fail. 
# 

#import marshal, imp 
#
#f   = open( 'PYTHONSCRIPT', 'rb' ) 
## 
## struct Header 
## { 
##     unsigned int    tag; 
##     unsigned int    optimize; 
##     unsigned int    unbuffered; 
##     unsigned int    data_bytes; 
##     unsigned char   zippath[VARIABLE_SIZE] 
## }; 
## 
## Skip the header, you have to know the header size beforehand. 
## 
#f.seek( 0x11 ) 
#ob  = marshal.load( f ) 
#
#for i in xrange( 0, len( ob ) ) : 
#    open( str( i ) + '.pyc', 'wb' ).write( imp.get_magic() + '\0' * 4 + marshal.dumps( ob[i] ) )
#
#f.close() 
# Embedded file name: rom0scan.py 
import sys, string, getopt, os, struct, socket, random, inspect, re 
import pycurl, Queue, itertools, collections 
from threading import Thread, RLock 
from cStringIO import StringIO 

class MyException(Exception): 

    def __init__(self, value = None): 
        self.value = value 

    def __str__(self): 
        return str(self.value) 

    def __repr__(self): 
        return repr(self.value) 


def itos32(num): 
    return struct.pack('=I', int(num & 4294967295L)) 


def uint16(num): 
    return int(struct.unpack('=H', struct.pack('=H', int(num & 65535)))[0]) 


def uint32(num): 
    return int(struct.unpack('=I', struct.pack('=I', int(num & 4294967295L)))[0]) 


def readb16(buf, index): 
    if index < 0: 
        index += len(buf) 
    return int(struct.unpack('>H', buf[index:index + 2])[0]) 


def readstr(buf, index): 
    if index < 0: 
        index += len(buf) 
    return buf[index:].split('\x00')[0] 


def resolvehost(host): 
    try: 
        ret = uint32(int(struct.unpack('>I', socket.inet_aton(socket.gethostbyname(host)))[0])) 
    except: 
        ret = 0 

    return ret 


def dosomething(str): 
    str += '\x00' 
    xxx = '' 
    i = 0 
    while i < len(str) - 1: 
        if '\\' != str[i]: 
            xxx += str[i] 
        elif i + 1 >= len(str): 
            xxx += str[i] 
        elif '\\' == str[i + 1]: 
            xxx += '\\' 
            i += 1 
        elif 'r' == str[i + 1]: 
            xxx += '\r' 
            i += 1 
        elif 'n' == str[i + 1]: 
            xxx += '\n' 
            i += 1 
        elif 't' == str[i + 1]: 
            xxx += '\t' 
            i += 1 
        elif '0' == str[i + 1]: 
            xxx += '\x00' 
            i += 1 
        elif 'x' == str[i + 1]: 
            if str[i + 2] >= '0' and str[i + 2] <= '9' or str[i + 2] >= 'a' and str[i + 2] <= 'f' or str[i + 2] >= 'A' and str[i + 2] <= 'F':
                i += 2 
                tmp = str[i] 
                if str[i + 1] >= '0' and str[i + 1] <= '9' or str[i + 1] >= 'a' and str[i + 1] <= 'f' or str[i + 1] >= 'A' and str[i + 1] <= 'F':
                    i += 1 
                    tmp += str[i] 
                else: 
                    tmp = '0' + tmp 
                xxx += tmp.decode('hex_codec') 
            else: 
                xxx += str[i] 
        else: 
            xxx += str[i] 
        i += 1 

    return xxx 


def AnyToSth(src, dst = 'utf_8'): 
    codelist = ['utf_8', 
     'gbk', 
     'gb18030', 
     'big5', 
     'latin_1'] 
    ret = '(error)' 
    for c in codelist: 
        try: 
            ret = src.decode(c).encode(dst) 
            break 
        except UnicodeDecodeError: 
            pass 
        except UnicodeEncodeError: 
            pass 

    return ret 


class BitReader(): 

    def __init__(self, bytes): 
        self.__bits__ = collections.deque() 
        for byte in bytes: 
            byte = ord(byte) 
            for i in xrange(8): 
                self.__bits__.append(byte >> 7 - i & 1) 

    def getBit(self): 
        return self.__bits__.popleft() 

    def getBits(self, num): 
        ret = 0 
        for i in xrange(num): 
            ret += self.getBit() << num - 1 - i 

        return ret 

    def getLength(self): 
        length = 2 
        while True: 
            i = self.getBits(2) 
            length += i 
            if not (3 == i and length < 8): 
                break 

        if 8 == length: 
            while True: 
                i = self.getBits(4) 
                length += i 
                if 15 != i: 
                    break 

        return length 


def LZSDecompress(data): 
    reader = BitReader(data) 
    result = '' 
    while True: 
        bit = reader.getBit() 
        if not bit: 
            byte = reader.getBits(8) 
            result += chr(byte) 
            continue 
        bit = reader.getBit() 
        if 1 == bit: 
            offset = reader.getBits(7) 
        else: 
            offset = reader.getBits(11) 
        if 1 == bit and 0 == offset: 
            break 
        if offset > len(result): 
            break 
        length = reader.getLength() 
        for i in xrange(length): 
            result += result[-offset] 

    return result 


QueueInWorkerExit = False 

class QueueInWorker(Thread): 

    def __init__(self, queue_in, queue_out, httpheader = [], proxypool = [], noproxy = 'localhost,127.0.0.1',\
     referer = '', followlocation = 1, maxredirs = 5, redir_protocols = 3, protocols = 3, connecttimeout = 30,\
      timeout = 30, connect_max = 16, monitor = False, port = None):
        super(QueueInWorker, self).__init__() 
        self.queue_in = queue_in 
        self.queue_out = queue_out 
        self.httpheader = httpheader 
        self.proxypool = proxypool 
        self.noproxy = noproxy 
        self.referer = referer 
        self.followlocation = followlocation 
        self.maxredirs = maxredirs 
        self.redir_protocols = redir_protocols 
        self.protocols = protocols 
        self.connecttimeout = connecttimeout 
        self.timeout = timeout 
        self.connect_max = connect_max 
        self.monitor = monitor 
        self.port = port 
        self.m = pycurl.CurlMulti() 
        self.m.cpool = [] 
        self.setDaemon(True) 

    def __del__(self): 
        if self.m is not None: 
            for c in self.m.cpool: 
                if c.host is not None: 
                    c.host = None 
                if c.head is not None: 
                    c.head.close() 
                    c.head = None 
                if c.body is not None: 
                    c.body.close() 
                    c.body = None 
                self.m.remove_handle(c) 
                self.m.cpool.remove(c) 
                c.close() 

            self.m.cpool = [] 
            self.m.close() 
            self.m = None 
        return 

    def c_init(self, c): 
        c.setopt(pycurl.HTTPHEADER, self.httpheader) 
        if len(self.proxypool) > 0: 
            c.setopt(pycurl.PROXY, random.choice(self.proxypool)) 
            #c.setopt(pycurl.NOPROXY, self.noproxy) 
        if self.referer is None: 
            c.setopt(pycurl.AUTOREFERER, 0) 
        elif '' == self.referer: 
            c.setopt(pycurl.AUTOREFERER, 1) 
        else: 
            c.setopt(pycurl.REFERER, self.referer) 
        c.setopt(pycurl.FOLLOWLOCATION, self.followlocation) 
#        c.setopt(pycurl.MAXREDIRS, self.maxredirs) 
        c.setopt(pycurl.MAXREDIRS, 0)#不进行跳转 
        #c.setopt(pycurl.REDIR_PROTOCOLS, self.redir_protocols) 
        #c.setopt(pycurl.PROTOCOLS, self.protocols) 
        c.setopt(pycurl.NOSIGNAL, 1) 
        c.setopt(pycurl.CONNECTTIMEOUT, self.connecttimeout) 
        c.setopt(pycurl.TIMEOUT, self.timeout) 
        c.setopt(pycurl.ENCODING, '') 
#        if self.port is not None: 
#            c.setopt(pycurl.PORT, self.port) 
        return 

    def run(self): 
        global QueueInWorkerExit 
        random.seed() 
        payloads = ['/.git/config','/.svn/entries']
        while True: 
            num = len(self.m.cpool) 
#            print 'while in master,num is ', num
#            if num >= self.connect_max:
#                for c in self.m.cpool:
#                    print c.getinfo(pycurl.EFFECTIVE_URL)
            if not QueueInWorkerExit and num < self.connect_max: 
                num = self.connect_max - num 
                for i in xrange(num): 
                    try: 
                        host = self.queue_in.get(True, 1) 
                        if host is None: 
                            QueueInWorkerExit = True 
                            break 
                        else: 
                            for payload in payloads:
                                if self.monitor: 
                                    sys.stderr.write('%40s\r%s\r' % (' ', host)) 
                                c = pycurl.Curl() 
                                self.c_init(c) 
                                c.host = host 
                                c.setopt(pycurl.URL, 'http://%s/%s' % (host, payload)) 
                                c.head = StringIO() 
                                c.setopt(pycurl.HEADERFUNCTION, c.head.write) 
                                c.body = StringIO() 
                                c.setopt(pycurl.WRITEFUNCTION, c.body.write) 
                                self.m.cpool.append(c) 
                                self.m.add_handle(c) 
                    except Queue.Empty: 
                        break 

            num = len(self.m.cpool) 
            if 0 == num: 
                if QueueInWorkerExit: 
                    self.queue_out.put(None) 
                    break 
                else: 
                    continue 
            while True: 
                ret, num_ret = self.m.perform() 
#                print 'while in perform,num_ret:',num_ret
                if pycurl.E_CALL_MULTI_PERFORM != ret: 
                    break 

            while True: 
                num_ret, ok_list, error_list = self.m.info_read() 
                #print 'while in get info,num_ret:',num_ret
                for c in ok_list: 
#                    head = AnyToSth(c.head.getvalue()) 
                    head = c.head.getvalue()
                    is_plain = False
                    if 'text/plain' in head:
                        is_plain = True
                    server = None
#                    if '(error)' == head: 
#                        server = '(error)' 
#                    else: 
#                        try: 
#                            server = re.search('Server: ([^\\r\\n]+)', head, re.U).group(1)
#                            server = AnyToSth(server, 'gbk') 
#                        except AttributeError: 
#                            server = None 

                    code = c.getinfo(pycurl.HTTP_CODE) 
#                    print 'code',code
                    if 200 == code: 
                        buf = c.body.getvalue() 
                        effective_url = c.getinfo(pycurl.EFFECTIVE_URL)
#                        print 'effective_url,buf',effective_url,buf
                        if is_plain:
                            if effective_url and effective_url.strip().endswith('config'):
                                if 'repositoryformatversion' in buf:
                                    self.queue_out.put((c.host, code, server, effective_url))
                                    print 'effective_url:',effective_url

                            if effective_url and effective_url.strip().endswith('entries'):
                                if 'dir' in buf:
                                    self.queue_out.put((c.host, code, server, effective_url)) 
                                    print 'effective_url:v1.6:',effective_url
                                elif re.match(r'^\d+.*', buf):
                                    self.queue_out.put((c.host, code, server, effective_url)) 
                                    print 'effective_url:v1.7:',effective_url

                    c.host = None 
                    c.head.close() 
                    c.head = None 
                    c.body.close() 
                    c.body = None 
                    self.m.remove_handle(c) 
                    self.m.cpool.remove(c) 
                    c.close() 

                for c, errno, errmsg in error_list: 
                    c.host = None 
                    c.head.close() 
                    c.head = None 
                    c.body.close() 
                    c.body = None 
                    self.m.remove_handle(c) 
                    self.m.cpool.remove(c) 
                    c.close() 

                if 0 == num_ret: 
                    break 

            self.m.select(1.0) 

        return 


QueueTmpWorkerExit = False 
QueueTmpNoneNum = 0 
QueueTmpRLock = RLock() 

class QueueTmpWorker(Thread): 

    def __init__(self, queue_in, queue_out, num_fetch, httpheader = [], proxypool = [], noproxy = 'localhost,127.0.0.1', \
        referer = '', followlocation = 1, maxredirs = 5, redir_protocols = 3, protocols = 3, connecttimeout = 30, timeout = 30, \
        connect_max = 16, port = None):
        super(QueueTmpWorker, self).__init__() 
        self.queue_in = queue_in 
        self.queue_out = queue_out 
        self.num_fetch = num_fetch 
        self.httpheader = httpheader 
        self.proxypool = proxypool 
        self.noproxy = noproxy 
        self.referer = referer 
        self.followlocation = followlocation 
        self.maxredirs = maxredirs 
        self.redir_protocols = redir_protocols 
        self.protocols = protocols 
        self.connecttimeout = connecttimeout 
        self.timeout = timeout 
        self.connect_max = connect_max 
        self.port = port 
        self.m = pycurl.CurlMulti() 
        self.m.cpool = [] 
        self.setDaemon(True) 

    def __del__(self): 
        if self.m is not None: 
            for c in self.m.cpool: 
                if c.data is not None: 
                    c.data = None 
                if c.head is not None: 
                    c.head.close() 
                    c.head = None 
                if c.body is not None: 
                    c.body.close() 
                    c.body = None 
                self.m.remove_handle(c) 
                self.m.cpool.remove(c) 
                c.close() 

            self.m.cpool = [] 
            self.m.close() 
            self.m = None 
        return 

    def c_init(self, c): 
        c.setopt(pycurl.HTTPHEADER, self.httpheader) 
        if len(self.proxypool) > 0: 
            c.setopt(pycurl.PROXY, random.choice(self.proxypool)) 
            c.setopt(pycurl.NOPROXY, self.noproxy) 
        if self.referer is None: 
            c.setopt(pycurl.AUTOREFERER, 0) 
        elif '' == self.referer: 
            c.setopt(pycurl.AUTOREFERER, 1) 
        else: 
            c.setopt(pycurl.REFERER, self.referer) 
        c.setopt(pycurl.FOLLOWLOCATION, self.followlocation) 
        c.setopt(pycurl.MAXREDIRS, self.maxredirs) 
#        c.setopt(pycurl.REDIR_PROTOCOLS, self.redir_protocols) 
#        c.setopt(pycurl.PROTOCOLS, self.protocols) 
        c.setopt(pycurl.NOSIGNAL, 1) 
        c.setopt(pycurl.CONNECTTIMEOUT, self.connecttimeout) 
        c.setopt(pycurl.TIMEOUT, self.timeout) 
        c.setopt(pycurl.ENCODING, '') 
        if self.port is not None: 
            c.setopt(pycurl.PORT, self.port) 
        return 

    def run(self): 
        global QueueTmpWorkerExit 
        global QueueTmpNoneNum 
        random.seed() 
        while True: 
            num = len(self.m.cpool) 
            if not QueueTmpWorkerExit and num < self.connect_max: 
                num = self.connect_max - num 
                for i in xrange(num): 
                    try: 
                        data = self.queue_in.get(True, 1) 
                        if data is None: 
                            QueueTmpRLock.acquire() 
                            QueueTmpNoneNum += 1 
                            QueueTmpRLock.release() 
                            if self.num_fetch == QueueTmpNoneNum: 
                                QueueTmpWorkerExit = True 
                                break 
                        else: 
                            c = pycurl.Curl() 
                            self.c_init(c) 
                            c.data = data 
                            c.setopt(pycurl.URL, 'http://%s/' % data[0]) 
                            c.head = StringIO() 
                            c.setopt(pycurl.HEADERFUNCTION, c.head.write) 
                            c.body = StringIO() 
                            c.setopt(pycurl.WRITEFUNCTION, c.body.write) 
                            c.setopt(pycurl.CUSTOMREQUEST, 'HEAD') 
                            c.setopt(pycurl.NOBODY, True) 
                            self.m.cpool.append(c) 
                            self.m.add_handle(c) 
                    except Queue.Empty: 
                        break 

            num = len(self.m.cpool) 
            if 0 == num: 
                if QueueTmpWorkerExit: 
                    self.queue_out.put(None) 
                    break 
                else: 
                    continue 
            while True: 
                ret, num_ret = self.m.perform() 
                if pycurl.E_CALL_MULTI_PERFORM != ret: 
                    break 

            while True: 
                num_ret, ok_list, error_list = self.m.info_read() 
                for c in ok_list: 
                    code = c.getinfo(pycurl.HTTP_CODE) 
                    if 401 == code: 
                        head = AnyToSth(c.head.getvalue()) 
                        if '(error)' == head: 
                            model = '(error)' 
                        else: 
                            try: 
                                model = re.search('WWW-Authenticate: Basic realm="(.+?)"', c.head.getvalue(), re.U).group(1) 
                                model = AnyToSth(model, 'gbk') 
                            except AttributeError: 
                                model = None 

                    else: 
                        model = '(%u)' % code 
                    self.queue_out.put((c.data[0], 
                     c.data[1], 
                     c.data[2], 
                     c.data[3], 
                     model)) 
                    c.data = None 
                    c.head.close() 
                    c.head = None 
                    c.body.close() 
                    c.body = None 
                    self.m.remove_handle(c) 
                    self.m.cpool.remove(c) 
                    c.close() 

                for c, errno, errmsg in error_list: 
                    model = '(%u:%s)' % (errno, errmsg) 
                    self.queue_out.put((c.data[0], 
                     c.data[1], 
                     c.data[2], 
                     c.data[3], 
                     model)) 
                    c.data = None 
                    c.head.close() 
                    c.head = None 
                    c.body.close() 
                    c.body = None 
                    self.m.remove_handle(c) 
                    self.m.cpool.remove(c) 
                    c.close() 

                if 0 == num_ret: 
                    break 

            self.m.select(1.0) 

        return 


class QueueOutWorker(Thread): 

    def __init__(self, queue_in, num_fetch, quiet = False): 
        super(QueueOutWorker, self).__init__() 
        self.queue_in = queue_in 
        self.num_fetch = num_fetch 
        self.quiet = quiet 
        self.setDaemon(True) 

    def __del__(self): 
        pass 

    def run(self): 
        num_none = 0 
        while True: 
            data = self.queue_in.get() 
            if data is None: 
                num_none += 1 
                if self.num_fetch == num_none: 
                    break 
            else: 
                host = data[0] 
                code = data[1] 
                server = data[2] 
                effective_url = data[3]
                print 'go to hack it:', host, code, server,effective_url
        return 

import argparse
from optparse import OptionParser
def main1():
    parser = argparse.ArgumentParser(description='git and svn scan')
    parser = OptionParser()
    parser.add_option('-f','--file',dest='file_path',help='读取文件',default=None)
    parser.add_option('-t','--time',dest='time_second',help='等待时间',default=30)
    parser.add_option('-n','--thread_num',dest='thread_num',help='线程数',default=8)
    parser.add_option('-b','--begin',dest='ip_begin',help='开始ip',default=None)
    parser.add_option('-e','--end',dest='ip_end',help='结束ip',default=None)
    options, args = parser.parse_args()
    file_path = options.file_path
    second = options.time_second
    connectnum = 80
    threadnum = int(options.thread_num)
    begin = options.ip_begin
    end = options.ip_end
    monitor = False
    quiet = False
    port = None
    head = None
    proxypool = []
    try:
        with open('/root/tool/proxy.txt', 'r') as fd_proxy:
            for line in fd_proxy:
                proxy = 'http://%s' %(line.strip())
                print 'proxy',proxy
                proxypool.append(proxy)
    except Exception,e:
        print 'can not open file proxy.txt'
#    proxypool = []

    httpheader = ['User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2;\
         .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET4.0C; .NET4.0E)',\
          'Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap,\
           application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*'] 


    queue_in = Queue.Queue(4096) 
    #queue_tmp = Queue.Queue(1024) 
    queue_out = Queue.Queue(4096) 
    for i in xrange(threadnum): 
        QueueInWorker(queue_in, queue_out, httpheader=httpheader, connect_max=connectnum, connecttimeout=second, timeout=second, monitor=monitor, port=port, proxypool=proxypool).start() 

    qoworker = QueueOutWorker(queue_out, threadnum, quiet) 
    qoworker.start() 
    count = 0
    if file_path:
        with open(file_path, 'r') as fd:
            for line in fd:
                line = line.strip()
                if line and line.split():
                    ip = line.split()[0].strip()
                    ip_port = ip + ":80"
                    queue_in.put(ip_port)
                    count = count + 1
                    if count %10000 == 0:
                        print 'count',count
                    #print 'ip_port',ip_port
    elif begin and end:
        for ip in itertools.islice(itertools.count(begin), end-begin):
            tail = ip&255
            if not tail or 255 == tail:
                continue
            ip = socket.inet_ntoa(itos32(socket.ntohl(ip)))
            queue_in.put(ip+":80")

    qoworker.join()



if '__main__' == __name__: 
    try: 
#        main(os.path.basename(sys.argv[0]), sys.argv[1:]) 
        main1()
    except KeyboardInterrupt: 
        pass 
