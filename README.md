# Some commands to run

Run in screen the following to run the data plane.
```sh
screen -r
./run_switchd.sh -p simple_forwarding
```

Set up the ports as follows
```sh
ucli
pm
port-add 31/0 40G NONE
port-add 32/0 40G NONE
an-set -/- 2
port-enb -/-
exit
```

Setting to show traffic rate at each port
```sh
bf-sde.pm> rate-period 1
bf-sde.pm> rate-show
```

Simple forwarding rules
```sh
bfrt.simple_forwarding.pipe.Ingress.forward.entry_with_send(ingress_port=196, port=132).push()
bfrt.simple_forwarding.pipe.Ingress.forward.entry_with_send(ingress_port=196, port=140).push()
```
