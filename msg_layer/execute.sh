cd ../
scp ./msg_layer/xdma.c vsn@192.168.2.67:/home/vsn/Desktop/popcorn-xdma/msg_layer/
scp ./kernel/popcorn/page_server.c ./kernel/popcorn/pcie.c ./kernel/popcorn/pcn_kmsg.c ./kernel/popcorn/bundle.c ./kernel/popcorn/wait_station.c ./kernel/popcorn/types.h ./kernel/popcorn/wait_station.h ./kernel/popcorn/syscall_redirect.c vsn@192.168.2.67:/home/vsn/Desktop/popcorn-xdma/kernel/popcorn/
scp ./include/popcorn/pcie.h ./include/popcorn/page_server.h ./include/popcorn/pcn_kmsg.h vsn@192.168.2.67:/home/vsn/Desktop/popcorn-xdma/include/popcorn/
make -j 12
sudo make INSTALL_MOD_SCRIPT=1 modules_install install 
