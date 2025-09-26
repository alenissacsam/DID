#!/usr/bin/env python3
import json, sys

def main():
    if len(sys.argv) < 3:
        print("", end="")
        return 0
    path = sys.argv[1]
    name = sys.argv[2]
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except Exception:
        print("", end="")
        return 0

    txs = data.get('transactions') or []
    addrs = [t.get('contractAddress') for t in txs if t.get('contractName') == name and t.get('contractAddress')]
    if addrs:
        print(addrs[-1], end="")
    else:
        print("", end="")

if __name__ == '__main__':
    sys.exit(main())
