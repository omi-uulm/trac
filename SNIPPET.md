# Local dev load snippets

```
apk add stress-ng fio iperf3
```

# CPU

```
stress-ng -c 1
```

# Mem

```
stress-ng --vm 1 --vm-bytes 2g --vm-keep
```

# Disk

```
fio --rw=randwrite --size=4k --filename=/tmp/outfile --time_based --rate_iops=250 --numjobs=4  --eta=never --ioengine=psync --direct=1 --sync=dsync --size=4k --name test
```

# Net

```
iperf3 -s -p 5000
iperf3 -c 172.17.0.2 -p 5000 -b 1Gi
```