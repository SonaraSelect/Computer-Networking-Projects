# Welcome to my adaptive streaming proxy

It intercepts the manifest file, causing the client to only request 500 kbps segments. However, it does not have the capability of adjusting the segment requests to find a suitable bitrate given the throughput. Of course, the proxy still logs everything that is asked for, and it will overwrite any previous tests, so once you run, the data I left behind will be gone.

In the proxy log you will see about 1 minute of unthrottled data with an alpha value of 1. As a result, it stays at a steady 500 kbps.


to run the proxy:
> python3 proxy.py proxy.log [alpha value]

to run the grapher:
> python3 grapher.py

thank you for viewing my project!
- Audrey