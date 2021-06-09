sudo PRECONFIGURED_TAPIF=tap1 ./receiver &
sleep 5
sudo PRECONFIGURED_TAPIF=tap0 ./sender &
sleep 5
pkill receiver
pkill sender
