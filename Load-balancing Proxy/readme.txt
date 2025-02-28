CSDS 325 - Audrey Michel - pjm173 - Project 1

This code is meant to run in linux ubuntu with the latest python3
You may have to symbolically link the servers to nginx as well. I did it on my machine but I'm not sure if you have to, too

Important note: the proxy will close after wrk testing finishes. You will have to restart the proxy per each test.

To run proxy:
python3 proxy.py servers.conf

To run wrk tests:
wrk -t10 -c1000 -d10s --latency http://127.0.0.1:9000/

To run apache benchmark tests:
ab -n 500 -c 10 -k http://127.0.0.1:9000/