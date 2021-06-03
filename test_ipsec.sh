cd build && cmake .. && make && cd -
cd ipsec_app && make clean && make all && cd -
sudo ./ipsec_app/app
