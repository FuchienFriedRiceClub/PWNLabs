#/bin/bash

nohup socat tcp-l:9527,reuseaddr,fork exec:./brop_example &
