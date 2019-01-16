#!/bin/bash

nohup forever -l ../logs/forever.log -o ../logs/server_out.log -e ../logs/server_err.log server.js &
