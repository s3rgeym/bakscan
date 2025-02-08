# BakScan

Simple and fast backup scanner written on Go.

Example:

```sh
nohup ./bakscan -k -i urls.txt > output.log 2>&1 &
```

Saved files will be stored in `output` directory.

See Help:

```sh
./bakscan -h
```
