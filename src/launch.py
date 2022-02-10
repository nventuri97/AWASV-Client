import os, sys, getopt, time, json
from lib.zapClient import ZapClient

def printHelp():
        print("usage: python3 client.py [option] ...")
        print("h, help         -- Display the help command")
        print("z, zap          -- The IP address where ZAP is running (default value is 127.0.0.1)")
        print("k, apikey       -- The API key to connect with ZAP API")
        print("proxy           -- The IP where ZAP is proxy (format ip-address:port")

argumentList=sys.argv[1:]
if len(argumentList)==0:
    sys.exit("Error! API key is required")

options="hz:p:k:"
long_options= ["help","zap=","port=","apikey=" "proxies="]

#Default value for ZAP initialization
zapIp="127.0.0.1"
proxy=None

try:
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)

    # checking each argument
    for (currentArgument, currentValue) in arguments:
        if currentArgument in ("-h", "--help"):
            printHelp()
            sys.exit()
        elif currentArgument in ("-z", "--zap-ip"):
            zapIp=currentValue
        elif currentArgument in ("-k", "--apikey"):
            apikey=currentValue
        elif currentArgument in ("proxy"):
            proxy=currentValue

except getopt.error as err:
    # output error, and return with an error code
    print(str(err))

client=ZapClient(zapIp, apikey, proxy)
while True:
    if os.path.isfile("./attackFile.json"):
        f=open("./attackFile.json")
        configAttack=json.load(f)
        report=client.execute(configAttack=configAttack)
        with open('./report.json', 'w') as f:
            f.write(report)
        
        #performe attack
        # os.remove("./attackFile.json")
        break
    else:
        print("Waiting for attack file")
        time.sleep(30)