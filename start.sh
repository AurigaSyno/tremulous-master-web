#!/bin/bash
python3 master.py --verbose 4 --max-servers 256 --ipv4 --listen-addr localhost --use_ws --ws_ports 40700 --ws_ports 40710 --ws_ports 40720 --port 30700 --port 30705 --port 30710
