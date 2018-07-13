# -*- coding: utf-8 -*-
import pcap
import dpkt

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
    c = cou()
    sniffer = pcap.pcap('ens192')
    sniffer.setfilter('tcp')
    try :
        for packet_time,packet_data in sniffer :
            print '>'*90
            try :
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
                    print 'DATA LEN:%d' % data_len
                    print 'dpkt DATA LEN:%d' % data_data_len
                    #table_print(str_to_hex(packet_data))
                    if (data_len == 0):
                        pass
                    else :
                        table_print(str_to_hex(packet.data.data.data))
                    print '<'*90
                    print
            except KeyboardInterrupt :
                print 'KeyboardInterrupt'
                c.get_table()
                exit(0)
            except Exception ,e:
                print '>>>>except,%s<<<<' % str(e)
    except KeyboardInterrupt :
        print 'KeyboardInterrupt'
        c.get_table()
        exit(0)
    except Exception ,e:
        print 'sniffer stop: %s ' % str(e)
        exit(1)