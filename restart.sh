#!/bin/bash
sudo nfd-stop >& /dev/null
sleep 1
sudo nfd-start >& /dev/null
sleep 1
nfdc set-strategy /org/openmhealth /localhost/nfd/strategy/multicast/%FD%01
