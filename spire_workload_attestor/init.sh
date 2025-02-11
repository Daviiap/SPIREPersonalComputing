#!/bin/bash

AGENT_SPIFFE_ID=spiffe://example.org/agent/01
WORKLOAD_SPIFFE_ID=spiffe://example.org/user/01

TOKEN=$(spire-server token generate -spiffeID $AGENT_SPIFFE_ID | awk '{print $2}')

spire-server entry create \
    -parentID $AGENT_SPIFFE_ID \
    -spiffeID $WORKLOAD_SPIFFE_ID \
    -selector user:name:jonh_doe

spire-agent run -joinToken $TOKEN
