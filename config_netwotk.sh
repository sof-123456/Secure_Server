#!/bin/bash

sudo ip netns add sender_ns
sudo ip netns add encrypt_ns
sudo ip netns add decrypt_ns
sudo ip netns add receiver_ns


ip netns list
sudo ip link add veth_s type veth peer name veth_e
sudo ip link add veth_e2 type veth peer name veth_d
sudo ip link add veth_d2 type veth peer name veth_r


sudo ip link set veth_s netns sender_ns
sudo ip link set veth_e netns encrypt_ns

sudo ip link set veth_e2 netns encrypt_ns
sudo ip link set veth_d netns decrypt_ns

sudo ip link set veth_d2 netns decrypt_ns
sudo ip link set veth_r netns receiver_ns

sudo ip netns exec sender_ns ip addr add 10.0.1.1/24 dev veth_s
sudo ip netns exec encrypt_ns ip addr add 10.0.1.2/24 dev veth_e

sudo ip netns exec encrypt_ns ip addr add 10.0.2.1/24 dev veth_e2
sudo ip netns exec decrypt_ns ip addr add 10.0.2.2/24 dev veth_d
sudo ip netns exec decrypt_ns ip addr add 10.0.3.1/24 dev veth_d2
sudo ip netns exec receiver_ns ip addr add 10.0.3.2/24 dev veth_r

sudo ip netns exec sender_ns ip link set lo up
sudo ip netns exec encrypt_ns ip link set lo up
sudo ip netns exec decrypt_ns ip link set lo up
sudo ip netns exec receiver_ns ip link set lo up

sudo ip netns exec sender_ns ip link set veth_s up
sudo ip netns exec encrypt_ns ip link set veth_e up
sudo ip netns exec encrypt_ns ip link set veth_e2 up
sudo ip netns exec decrypt_ns ip link set veth_d up
sudo ip netns exec decrypt_ns ip link set veth_d2 up
sudo ip netns exec receiver_ns ip link set veth_r up

sudo ip netns exec encrypt_ns sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec decrypt_ns sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec sender_ns ip route add default via 10.0.1.2

sudo ip netns exec encrypt_ns ip route add 10.0.3.0/24 via 10.0.2.2

sudo ip netns exec decrypt_ns ip route add 10.0.1.0/24 via 10.0.2.1

sudo ip netns exec receiver_ns ip route add default via 10.0.3.1



# sudo ip netns exec decrypt_ns ./decrypt_server  
# sudo ip netns exec encrypt_ns ./encrypt_server
# sudo ip netns exec receiver_ns nc -u -l -p 1114
# sudo ip netns exec sender_ns nc -u 10.0.3.2 1114
#sudo ip netns exec encrypt_ns ip link show  
#sudo ip netns exec  decrypt_ns   tcpdump -i veth_d -nn
