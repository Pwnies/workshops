#!/bin/bash

docker build -t hackenv . && docker run -it hackenv bash
