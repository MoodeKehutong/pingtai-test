#!/bin/bash

kill `cat ./tmp/pids/unicorn.pid`
unicorn_rails -p 3333 -D
