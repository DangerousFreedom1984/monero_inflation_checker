"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import copy


url_str = 'http://localhost:18081/'
def node_choice(choice):
    global node_conn
    global url_str 

    node_conn = copy.copy(choice)

    if node_conn == 0:
        url_str = 'http://node.sethforprivacy.com:18089/'
    else:
        url_str = 'http://localhost:18081/'
