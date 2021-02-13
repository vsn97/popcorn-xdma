echo "Transferring xdma.c and starting make"
scp ./xdma.c vsn@192.168.2.67:/home/vsn/Desktop/popcorn-xdma/msg_layer/
cd ../
make -j 12
sudo make INSTALL_MOD_SCRIPT=1 modules_install install 

echo "Done"
