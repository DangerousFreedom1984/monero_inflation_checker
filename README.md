# Monero Inflation Checker

This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero) and
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)

"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.

## TLDR

Minimal Python tools and educational material for checking inflation in Monero.
You can get more information at [moneroinflation.com](https://moneroinflation.com/).

## What is it?

MIC offers minimal Python tools to check transactions, emission curve, ring signatures, zero-knowledge proofs and others to prove that there is no inflation happening in Monero.

The tools here are just for educational purposes. They are not ready for production. 

## Installation and requirements

Please install the required packages inside a new virtual environment with:

> python3 -m venv .vmic

> source .vmic/bin/activate

> pip install -r requirements.txt

There are two options to use the MIC verifier.

1) Using your own full node. The standard connection parameters are:

> username,password = 'username','password'

> rpc_connection = AuthServiceProxy(service_url='http://{0}:{1}@127.0.0.1:18081/json_rpc'.format(username, password))

2) Using a public node. The standard public node is from Seth for Privacy ('http://node.sethforprivacy.com:18089/')

You can change the connection parameters at 'com_db.py' according to your needs.

## Running MIC

After installing the required packages, you can simply type:

> python3 MIC.py

## Contact

Feel free to reach out at monero-inflation-checker@protonmail.com

If you think that this work taught you something or if you want to see it growing, please consider donating to: 
42ABfi8JdQTjbByuCHiP2fLzScit6tKGh8nhXWvdjwYv4NBEgdZ85hrVF34h2gGU8K76UBEp1mxz1VT4DbGkqNutQW9EXHj
