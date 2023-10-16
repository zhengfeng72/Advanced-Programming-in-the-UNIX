
test1:
	./launcher ./sandbox.so config.txt cat /etc/passwd

test2:
	./launcher ./sandbox.so config.txt cat /etc/hosts

test3:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem

test5:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1

test6:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1

test7:
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1

test8:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'

sd:
	gcc -o sandbox.so sandbox.c -Wall -g -shared -fPIC -ldl

tmpsd:
	gcc -o sandbox.so tmp_sandbox.c -Wall -g -shared -fPIC -ldl

clean:
	rm sandbox.so