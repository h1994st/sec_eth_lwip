PRECONFIGURED_TAPIF=tap0 ./receiver &
sleep 5
PRECONFIGURED_TAPIF=tap1 ./sender &
sleep 5
pkill receiver
pkill sender
