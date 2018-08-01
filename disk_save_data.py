import redis 
import time
import cPickle
import os

def get_data_sync(db,data):
    rs = conn_redis('localhost',6379,db)
    if rs.get('lock') == '0' :
        for d in xrange(10000):
            data.append(rs.hgetall(d))
        rs.flushdb()
        print len(data)
        print 'DB: %s , Data OK' % db
    else :
        print 'DB: %s , Data: %s' % (db,rs.get('lock'))

def conn_redis(redis_host,redis_port,redis_db):
    return redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)

def get_file(dir):
    l = []
    for dirpath, dirnames, filenames in os.walk(dir):
        for filepath in filenames:
            l.append(int(filepath.split('.')[1]))
    if len(l) == 0:
        l.append(0)
    return l

if __name__ == '__main__':
    savedir = '/sdbdata/data'
    count = max(get_file(savedir)) + 1
    print count
    try :
        while(1):
            data = []
            for db in xrange(32):
                print db
                t1 = time.time()
                get_data_sync(db,data)
                print time.time()-t1
                print
            t1 = time.time()
            if len(data) == 0 :
                print 'null loop'
            else :
                print 'save data to disk'
                f = open('/sdbdata/data/data_py.%s' % count ,'wb')
                cPickle.dump(data,f)
                print time.time()-t1
                count += 1
            time.sleep(0.1)
    except KeyboardInterrupt :
        print 'save data to disk'
        f = open('/sdbdata/data/data_py.%s' % count ,'wb')
        cPickle.dump(data,f)
        print time.time()-t1
        count += 1
        exit(0)
    except Exception ,e:
        print 'Exception stop: %s ' % str(e)
        exit(1)
