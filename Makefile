OBJS = utils.o dkim_milter.o firm-dkim.o
CC = gcc
LDFLAGS = -lmilter -pthread  -lnsl -lresolv -fPIC  -lcrypto 
CFLAGS =  -g -Wall  -I.  -fPIC -lcrypto

again : clean dkim_milter

dkim_milter : $(OBJS)
	$(CC) -o dkim_milter $(OBJS) $(LDFLAGS)

utils.o :	
	$(CC) $(CFLAGS) -c utils.c
clean :
	rm -f dkim_milter *.o *~
tags:
	find -L  .  -name '*.cpp' -o -name '*.h' -o -name '*.c' | xargs etags

firm-dkim:	$(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -shared -Wl,-soname,libfirm-dkim.so -o libfirm-dkim.so

firm-dkim.o:	
		$(CC) $(CFLAGS) -c firm-dkim.c -o firm-dkim.o

install:
	mkdir /opt/dkim
	cp -vf * /opt/dkim
	cp -vf init_milter /etc/init.d/dkmilter
	mkdir -p /var/run/dkim
	chown postfix:mail /var/run/dkim
	



start:
	su  -c "rm -f /var/run/dkim/f1.sock; /opt/dkim/dkim_milter /opt/dkim/dkim.conf" postfix

stop:
	kill `cat /var/run/dkim/dkim.pid `