#!/bin/sh
cd "$(dirname "$0")/.." && sudo containerlab deploy -t topology.clab.yml --reconfigure