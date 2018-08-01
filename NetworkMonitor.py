# -*- coding: utf-8 -*-
import pcap
import dpkt
import time
import redis

class redis_election():
    def __init__(self):
        self.redis_host = '127.0.0.1'
        self.redis_port = 6379
        self.redis_db = -1
        self.lock_dic = dict.fromkeys(range(32), 0)
    def conn_redis(self):
        return redis.StrictRedis(host=self.redis_host, port=self.redis_port, db=self.redis_db)
    def get_rs(self):
        self.redis_db += 1
        if self.redis_db < len(self.lock_dic) :
            pass
        else :
            self.redis_db = 0
        if 0 in self.lock_dic.values() :
            pass
        else :
           print 'DB Poll Full'
           return self.rs
        if self.lock_dic[self.redis_db] != 1:
            self.rs = self.conn_redis()
            if self.rs.get('lock') != 1:
                self.rs.set('lock',1)
                self.lock_dic[self.redis_db] = 1
            else :
                self.get_rs()
                self.lock_dic[self.redis_db] = 1
        else :
            self.get_rs()
        return self.rs
    def give_back(self):
        self.lock_dic[self.redis_db] = 0
        self.rs.set('lock',0)

def get_time_stamp():
    ct = time.time()
    local_time = time.localtime(ct)
    data_head = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
    data_secs = (ct - long(ct)) * 1000
    time_stamp = "%s.%03d" % (data_head, data_secs)
    return time_stamp

class cou():
    def __init__(self):
        self.src_dic = {}
    def src_add(self,src_ip,len):
        if self.src_dic.has_key(src_ip) :
            pass
        else :
            self.src_dic[src_ip] = 0 
        self.src_dic[src_ip] = self.src_dic[src_ip]+len
    def get_table(self):
        print '{:^5}|{:^16}|{:^16}'.format('','IP ADDR','LEN')
        print '-'*38
        row = 0
        for l in sorted(c.src_dic.items(),key = lambda x:x[1],reverse = True):
            print '{:^5}|{:<16}|{:<16}'.format(row,l[0],l[1])
            row += 1
        print '-'*38

def table_print(s):
    l = s.split(' ')
    print '{:^8}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|'.format('','0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F')
    print '-'*90
    pl = [l[i:i+16] for i in xrange(0,len(l),16)]
    row = 0
    for p in pl :
        p.insert(0,'0x%s0' %str.upper(str(hex(row)).replace('0x', '')))
        if len(p)<17 :
            for i in xrange(17-len(p)):
                p.append('')
        #print '{:^8}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|'.format(p)
        print '{:^8}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|{:^4}|'.format(p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],p[16])
        row += 1

def str_to_hex(s):
    r = ''
    for c in s:
        h = hex(ord(c)).replace('0x', '')
        if (len(h) == 1):
            h = '0%s' % h
        r = '%s%s '% (r,h)
    return str.upper(r)

def toip(ip):
    return '.'.join('%s' % n for n in ip)

if __name__ == '__main__' :
    rse = redis_election()
    rs = rse.get_rs()
    c = cou()
    sniffer = pcap.pcap('ens192')
    sniffer.setfilter('tcp')
    count = 0
    try :
        for packet_time,packet_data in sniffer :
            print '>'*90
            count += 1
            try :
                t = get_time_stamp()
                packet = dpkt.ethernet.Ethernet(packet_data)
                src_ip = tuple(map(ord,list(packet.data.src)))
                src_port = packet.data.data.sport
                dst_ip = tuple(map(ord,list(packet.data.dst)))
                dst_port = packet.data.data.dport
                data_len = len(packet_data)
                data_data_len = len(packet.data.data.data)
                if (src_ip[0] == 192):
                    c.src_add(toip(src_ip),1)
                else :
                    pass
                if (toip(src_ip) == '127.0.0.1'):
                    pass
                else :
                    print 'SRC:%s:%s' % (toip(src_ip),src_port)
                    print 'DST:%s:%s' % (toip(dst_ip),dst_port)
                    '''
                    print 'DATA LEN:%d' % data_len
                    print 'dpkt DATA LEN:%d' % data_data_len
                    #table_print(str_to_hex(packet_data))
                    if (data_len == 0):
                        pass
                    else :
                        table_print(str_to_hex(packet.data.data.data))
                    '''
                    print '<'*90
                    print
                if count == 10001:
                    count = 1
                    rse.give_back()
                    rs = rse.get_rs()
                else :
                   pass
                rs.hmset(count,{'src_ip':toip(src_ip),'src_port':src_port,'dst_ip':toip(dst_ip),'dst_port':dst_port,'data_len':data_len,'data':packet_data,'time':t})
            except KeyboardInterrupt :
                rse.give_back()
                print 'KeyboardInterrupt'
                c.get_table()
                exit(0)
            except Exception ,e:
                print '>>>>except,%s<<<<' % str(e)
    except KeyboardInterrupt :
        rse.give_back()
        print 'KeyboardInterrupt'
        c.get_table()
        exit(0)
    except Exception ,e:
        print 'sniffer stop: %s ' % str(e)
        exit(1)
