# 1) Stop the driver so it can't respawn the stack
pkill -f 'zigbeeOnHostDriver|zigbeeonhostTester|python3 .*zigbee-fuzzer/py' 2>/dev/null || true
sleep 0.5

# 2) Kill whoever is listening on :6000 (the stack)
lsof -tiTCP:6002 -sTCP:LISTEN | xargs -r kill -INT
sleep 1
lsof -tiTCP:6002 -sTCP:LISTEN | xargs -r kill -TERM
sleep 1
lsof -tiTCP:6002 -sTCP:LISTEN | xargs -r kill -KILL

# 3) Clean up npm/node wrappers just in case
pkill -f 'npm run dev:cli' 2>/dev/null || true
pkill -f 'node .*dev:cli'  2>/dev/null || true

# 4) Verify it's gone
ss -lntp | grep ':6002' || echo "no listener on 6000"

