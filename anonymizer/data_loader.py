import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig

import json
import os
from os import system, name
import time

IP_ADDRESS = "NULL"
PORT = "-1"

SUPPORTED_ENTITIES = ['IBAN_CODE', 'US_PASSPORT', 'DATE_TIME', 'MEDICAL_LICENSE', 'CRYPTO', 'LOCATION', 'UK_NHS', 'US_SSN', 'CREDIT_CARD', 'US_BANK_NUMBER', 'US_ITIN', 'EMAIL_ADDRESS', 'PERSON', 'IP_ADDRESS', 'DOMAIN_NAME', 'PHONE_NUMBER', 'SG_NRIC_FIN', 'NRP', 'US_DRIVER_LICENSE']
ANONYMIZERS = ['hash', 'mask', 'redact', 'replace', 'custom', 'encrypt', 'decrypt']

CONFIG_FILE = 'config/operatorConfigAnonymizer.txt'
CONFIG_FILE_DE = 'config/operatorConfigDeanonymizer.txt'

PATH_ANONYMIZER_RESULTS = "../anonymizer-results/"
PATH_ANALYZER_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

### UTILITY FUNCTIONS

def clear():

    if name == "nt":
        _ = system("cls")
    else:
        _ = system("clear")

def exit():

    while True:
        if input("\nPress q to exit: ").lower() == "q":
            clear()
            break

def checkDuplicate(entity_type, configFile):
    
    try:
        with open(configFile, 'r') as f:
            for line in f:
                if entity_type in line:
                    print("\nCONFIG: config entry type already exists: {}".format(line))
                    response = input("Do you want to reset your conf file? [Y/N]: ").upper()
                    
                    if response == "Y":
                        print("CONFIG: resetting config file")
                        return 1
                    else:
                        print("CONFIG: ignoring...")
                        return 0

    except IOError:
        print("CONFIG: creating a new config file...")

    return -1

def readConfiguration(configFile):

    with open(configFile, "r") as ConfigFile:
        print("\n")
        for line in ConfigFile:
            print(line.strip().replace("\"", ""))
        print("\n")

    exit()


def makeMessage(msg):
    
    return pb2.DataFile(chunk = msg)

def generateChunks(filename):
    
    global TOTAL_CHUNKS
    cont = 0

    try:
        textFile = open(filename + ".txt", "r")

        while True:
            data = textFile.read(CHUNK_SIZE)

            if not data:
                textFile.close()
                break
            
            cont += CHUNK_SIZE
            TOTAL_CHUNKS = cont

            yield makeMessage(data)

    except IOError:
        print("{} not exists!".format(filename))
        yield -1

def sendRequestForText(stub, filename, uuidClient, requestType):
    
    responses = stub.getText(pb2.Request(uuidClient = uuidClient, type = requestType))

    if requestType == "anonymize":
        with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymized.txt", "w") as AnonymizerResults:
            for response in responses:
                if response.chunk == -1:
                    # received a NAK
                    print("FROM SERVER: Error during anonymization")
                else:
                    AnonymizerResults.write(response.chunk)
                    print("{}-anonymized.txt created".format(filename))

    else:
        with open(PATH_ANONYMIZER_RESULTS + filename + "-deanonymized.txt", "w") as DeanonymizerResults:
            for response in responses:
                if response.chunk == -1:
                    # received a NAK
                    print("FROM SERVER: Error during deanonymization")
                else:
                    DeanonymizerResults.write(response.chunk)
                    print("{}-deanonymized.txt created".format(filename))


def sendRequestForItems(stub, filename, uuidClient, requestType):
    
    responses = stub.getItems(pb2.Request(uuidClient = uuidClient, type = requestType))

    if requestType == "anonymize":
        with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt", "w") as AnonymizerItemsResults:
            for response in responses:
                AnonymizerItemsResults.write('{' + f' "operator": "{response.operator}", "entity_type": "{response.entity_type}", "start": {response.start}, "end": {response.end}, "text": "{response.text}" ' + '}\n')

        print("{}-anonymize-items.txt created".format(filename))
        exit()
        clear()

    else:
        with open(PATH_ANONYMIZER_RESULTS + filename + "-deanonymize-items.txt", "w") as DeanonymizerItemsResults:
            for response in responses:
                DeanonymizerItemsResults.write('{' + f' "start": {response.start}, "end": {response.end}, "operator": "{response.operator}", "text": "{response.text}", "entity_type": "NUMBER" ' + '}\n')

        print("{}-deanonymize-items.txt created".format(filename))
        exit()
        clear()

### START ANONYMIZER SECTION

def addOperator(entity_type, params, configFile):

    with open(configFile, 'a') as f:
        f.write(f'"{entity_type}" : "{params}"\n')

def anonymizer_options(anonymizer, configType):
    # RITORNA UNA STRINGA in base al tipo di anonymizer
    # { "type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_end": true }  { "type": "redact" } { "type": "replace", "new_value": "NEW VALUE" }  
    # { "type": "encrypt", "key": "string" }  { "type": "hash", "hash_type": "string" }

    if configType == "Anonymizer":
        if anonymizer == "replace":
            
            print("** replace **")
            new_value = input("New value: ")
            options = '{' + f"\'type\': \'{anonymizer}\', \'new_value\': \'{new_value}\'" + '}'

        elif anonymizer == "redact":

            print("** redact **")
            options = '{' + f"\'type\': \'{anonymizer}\'" + '}'

        elif anonymizer == "mask":

            print("** mask **")
            masking_char = input("Masking char: ")
            chars_to_mask = input("Chars to mask: ")
            from_end = input("From end (0 or 1): ")
            options = '{' + f"\'type\': \'{anonymizer}\', \'masking_char\': \'{masking_char}\', \'chars_to_mask\': {chars_to_mask}, \'from_end\': {from_end}" + '}'
        
        elif anonymizer == "hash":
            
            print("** hash **")
            hash_type = input("Hash type (md5, sha256, sha512): ").lower()

            if hash_type == "md5" or hash_type == "sha256" or hash_type == "sha512":
                options = '{' + f"\'type\': \'{anonymizer}\', \'hash_type\': \'{hash_type}\'" + '}'
            else:
                print("Hash type error\n")
                return -1

        elif anonymizer == "encrypt":
            
            print("** encrypt **")
            key = input("Key: ")
            options = '{' + f"\'type\': \'{anonymizer}\', \'key\': \'{key}\'" + '}'

        else:
            print("CONFIG: Invalid anonymizer\n")
            return -1

    elif configType == "Deanonymizer":
        # DEANONYMIZER SUPPORTS ONLY DECRYPT ANONYMIZER
        if anonymizer == "decrypt":
            
            print("** decrypt **")
            key = input("Key: ")
            options = '{' + f"\'type\': \'{anonymizer}\', \'key\': \'{key}\'" + '}'

        else:
            print("CONFIG: Invalid anonymizer\n")
            return -1

    else:
        print("ConfigType error")
        return -1

    #print("\nAdded ({}): {}\n".format(anonymizer, options))
    return options

def setupConfig(configFile):

    #print("{}".format(configFile))

    if configFile == CONFIG_FILE:
        configType = "Anonymizer"
    elif configFile == CONFIG_FILE_DE:
        configType = "Deanonymizer"
    else:
        print("ConfigFile not valid!")

    if os.path.exists(configFile):
        print("\nCONFIG: {} found".format(configFile))
        res = input("Do you want to reset the configuration? [Y/N] ").upper()

        if res == "Y":
            os.remove(configFile)
    
    print("\n{} Operator config (press Q for exit)\n".format(configType))
    
    while True:
        entity_type = input("Entity: ").upper()

        # QUITTING
        if entity_type == "Q" or entity_type == "QUIT":
            print("Quitting config..")
            clear()
            break

        # NOT EXISTS
        if entity_type.upper() not in SUPPORTED_ENTITIES:
            print("CONFIG: entity '{}' not exits\n".format(entity_type))
            continue
                
        # CHECK FOR DUPLICATES
        check = checkDuplicate(entity_type, configFile) 

        if check == 1:
            os.remove(configFile)
        elif check == 0:
            continue

        # return -1 from check()

        anonymizer = input("Anonymizer: ").lower()

        if anonymizer not in ANONYMIZERS:
            print("CONFIG: anonymizer '{}' not exists\n".format(anonymizer))
            continue

        # get params   
        params = anonymizer_options(anonymizer, configType)
        
        # save config
        if params != -1:
            addOperator(entity_type, params, configFile)
            print("\n{} -> {} - Config successfully updated.\n".format(entity_type, params))

def ReadResults(filename, uuidClient):
    
    with open(PATH_ANALYZER_RESULTS + filename + "-results.txt", "r") as resultsFile:
        for line in resultsFile:
            item = json.loads(line)
            yield pb2.RecognizerResult(uuidClient = uuidClient, start = item['start'], end = item['end'], score = item['score'], entity_type = item['entity_type'])
        
def sendRequestAnonymize(stub, filename, config):

    # sending original text to anonymize
    chunk_iterator = generateChunks(PATH_FILES + filename)
    print("\nFROM CLIENT: sending original text...")
    response = stub.sendFile(chunk_iterator)
    uuidClient = response.uuidClient

    if response.chunks == TOTAL_CHUNKS:
        print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

        # sending analyzer results
        print("FROM CLIENT: sending analyzer results...")
        response = stub.sendRecognizerResults(ReadResults(filename, uuidClient))

        if response.uuidClient == uuidClient:
            print("FROM SERVER: analyzer results received correctly. UUID: {}".format(uuidClient))

            # sending configuration file
            if config:
                print("FROM CLIENT: sending file config...")

                with open(CONFIG_FILE, "r") as configFile:
                    response = stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = configFile.read(), type = "anonymize"))

                    # ACK FROM SERVER: chunks is insignificant and uuidClient is used for acking
                    if response.chunks == -1 and response.uuidClient == uuidClient:  
                        print("FROM SERVER: configuration file received correctly")
                    else:  
                        print("FROM SERVER: configuration file not received correctly")  
            else:
                print("FROM CLIENT: using a default configuration")
            
            print("\nWaiting for Microsoft Presidio Anonymizer...")
            sendRequestForText(stub, filename, uuidClient, "anonymize")
            sendRequestForItems(stub, filename, uuidClient, "anonymize")

        else:
            print("FROM SERVER: analyzer results not received correctly.")

    else:
        print("FROM SERVER: original text file not received correctly")


def presidio_anonymizer_start():

    try:
        with grpc.insecure_channel(IP_ADDRESS + ':' + PORT) as channel:
            
            print("SERVER INFO: {}:{}".format(IP_ADDRESS, PORT))
            stub = pb2_grpc.AnonymizerEntityStub(channel)

            while True:
                print("\n1) Setup config file")
                print("2) Read the current config")
                print("3) Start anonymization")
                print("4) Back")

                command = int(input("\nCommand: "))
        
                if command == 1:
                    
                    setupConfig(CONFIG_FILE)

                elif command == 2:

                    if os.path.exists(CONFIG_FILE):
                        readConfiguration(CONFIG_FILE)
                    else:
                        print("Configuration file not found!")

                elif command == 3:

                    filename = input("\nFilename: ")

                    # check on files
                    filesExist = 0
                    if os.path.exists(PATH_FILES + filename + ".txt") and os.path.exists(PATH_ANALYZER_RESULTS + filename + "-results.txt"):
                        filesExist = 1

                    if filesExist == 0:
                        print("ERROR: file text or analyzer results not found!")
                        continue

                    # check configuration file
                    configUp = 0
                    if os.path.exists(CONFIG_FILE):
                        configUp = 1

                    if configUp == 0:
                        print("Config file not found! (Using a default conf)")
                        enableConfig = input("Do you want to use a default configuration? [Y/N] ").upper()

                        if enableConfig == "Y":
                            print("Anonymize with a default configuration")
                            sendRequestAnonymize(stub, filename, 0)

                        else:
                            print("Setup a config file")
                            continue
                    else:
                        print("Config file found!")
                        sendRequestAnonymize(stub, filename, 1)

                elif command == 4:
                    break
                else:
                    print("\nCommand not valid!")
                    
    except grpc.RpcError as rpc_error:
        if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
            print("Cannot connect to the server\n")
        else:
            print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")
    

### STOP ANONYMIZER SECTION

def ReadAnonymizedItems(filename, uuidClient):
    
    with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt", "r") as itemsFile:
        for line in itemsFile:
            item = json.loads(line)
            yield pb2.AnonymizedItem(uuidClient = uuidClient, start = item['start'], end = item['end'], entity_type = item['entity_type'], operator = item['operator'])


def sendRequestDeanonymize(stub, filename):

    # sending anonymized text (UUID = 0 INSIGNIFICANT)
    chunk_iterator = generateChunks(PATH_ANONYMIZER_RESULTS + filename + "-anonymized")
    print("\nFROM CLIENT: sending anonymized text...")
    response = stub.sendFile(chunk_iterator)
    uuidClient = response.uuidClient

    if response.chunks == TOTAL_CHUNKS:
        print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

        # sending items results
        print("FROM CLIENT: sending items...")
        response = stub.sendAnonymizedItems(ReadAnonymizedItems(filename, uuidClient))

        if response.uuidClient == uuidClient:
            print("FROM SERVER: analyzer results received correctly. UUID: {}".format(uuidClient))

            # sending configuration file (IS REQUIRED!)
            print("FROM CLIENT: sending file config...")

            with open(CONFIG_FILE_DE, "r") as configFile:
                response = stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = configFile.read(), type = "deanonymize"))

                # ACK FROM SERVER: chunks is insignificant and uuidClient is used for acking
                if response.chunks == -1 and response.uuidClient == uuidClient:  
                    print("FROM SERVER: configuration file received correctly")
                else:  
                    print("FROM SERVER: configuration file not received correctly")  
            
            print("\nWaiting for Microsoft Presidio Anonymizer...")
            sendRequestForText(stub, filename, uuidClient, "deanonymize")
            sendRequestForItems(stub, filename, uuidClient, "deanonymize")

        else:
            print("FROM SERVER: items results not received correctly.")

    else:
        print("FROM SERVER: anonymized text file not received correctly")


def presidio_deanonymizer_start():
    
    try:
        with grpc.insecure_channel(IP_ADDRESS + ':' + PORT) as channel:
            
            print("SERVER INFO:  {}:{}".format(IP_ADDRESS, PORT))
            stub = pb2_grpc.AnonymizerEntityStub(channel)

            while True:
                print("\n1) Setup config file")
                print("2) Read the current config")
                print("3) Start deanonymization")
                print("4) Back")

                command = int(input("\nCommand: "))
        
                if command == 1:
                    
                    setupConfig(CONFIG_FILE_DE)

                elif command == 2:

                    if os.path.exists(CONFIG_FILE_DE):
                        readConfiguration(CONFIG_FILE_DE)
                    else:
                        print("Configuration file not found!")

                elif command == 3:

                    filename = input("\nFilename: ")

                    # check on files
                    filesExist = 0
                    if os.path.exists(PATH_FILES + filename + ".txt") and os.path.exists(PATH_ANALYZER_RESULTS + filename + "-results.txt"):
                        filesExist = 1

                    if filesExist == 0:
                        print("ERROR: file text or analyzer results not found!")
                        continue

                    # check configuration file (FOR DEANONYMIZATION IS REQUIRED!)
                    if os.path.exists(CONFIG_FILE_DE) == 0:
                        print("Config file not found!")
                        print("You have to setup a config file before deanonymize")
                        continue
                    else:
                        print("Config file found!")
                        sendRequestDeanonymize(stub, filename)

                elif command == 4:
                    break
                else:
                    print("\nCommand not valid!")

    except grpc.RpcError as rpc_error:
        if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
            print("Cannot connect to the server\n")
        else:
            print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")


if __name__ == "__main__":

    while True:
        clear()
        print(":::::::::::::::::: PRESIDIO ANONYMIZER (data loader) ::::::::::::::::::\n")
        print("1) Anonymize")
        print("2) Deanonymize")
        print("3) Server configuration")
        print("4) Quit")

        try:
            command = int(input("\nCommand: "))
        except ValueError:
            print('\nYou did not enter a valid command\n')
            continue

        if command == 1:
            clear()
            
            if IP_ADDRESS == "NULL" or PORT == "-1":
                print("No server info found!")
                exit()
            else:
                presidio_anonymizer_start()

        elif command == 2:
            clear()
            
            if IP_ADDRESS == "NULL" or PORT == "-1":
                print("No server info found!")
                exit()
            else:
                presidio_deanonymizer_start()     
            
        elif command == 3:

            IP_ADDRESS = input("\nIP ADDRESS: ")
            PORT = input("SERVER PORT: ")
            exit()

        elif command == 4:
            print("\nQuitting..")
            time.sleep(1)
            break
        else:
            print("\nCommand not valid!\n") 
            clear() 