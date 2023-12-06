obj-m += kkit.o
kkit-objs := main.o helpers.o kubekit.o logging.o syscall_hooks.o

all: kkit json_parser

kkit:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
docker:
	cp main.c main.bak
	cp docker.c main.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mv main.bak main.c

json_parser:
	git clone https://github.com/DaveGamble/cJSON.git
	cd cJSON && \
	mkdir build && \
	cd build && \
	cmake .. -DBUILD_SHARED_AND_STATIC_LIBS=On && \
	make && \
	sudo make install
	gcc json_handler.c -o json_handler.out -l:libcjson.a

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm json_handler.out
	rm -rf cJSON
