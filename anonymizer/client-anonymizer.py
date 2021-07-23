import grpc 
from proto import service_anon_pb2_grpc as pb2_grpc
from proto import service_anon_pb2 as pb2

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig

import json
import os
import time

SUPPORTED_ENTITIES = ['IBAN_CODE', 'US_PASSPORT', 'DATE_TIME', 'MEDICAL_LICENSE', 'CRYPTO', 'LOCATION', 'UK_NHS', 'US_SSN', 'CREDIT_CARD', 'US_BANK_NUMBER', 'US_ITIN', 'EMAIL_ADDRESS', 'PERSON', 'IP_ADDRESS', 'DOMAIN_NAME', 'PHONE_NUMBER', 'SG_NRIC_FIN', 'NRP', 'US_DRIVER_LICENSE']
ANONYMIZERS = ['hash', 'mask', 'redact', 'replace', 'custom', 'encrypt', 'decrypt']

CONFIG_FILE = 'operatorConfig.txt'
CONFIG_FILE_DE = 'operatorDeConfig.txt'

PATH_ANONYMIZER_RESULTS = "../anonymizer-results/"
PATH_ANALYZER_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

### UTILITY FUNCTIONS

def check_duplicate(entity_type, configFile):
    
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

def read_configuration(configFile):

    with open(configFile, "r") as ConfigFile:
        for line in ConfigFile:
            print(line.strip().replace("\"", ""))

def make_message(msg, uuid, requestType):
    
    if uuid:
        return pb2.DataFile(uuidClient = uuid, chunk = msg)

    return pb2.DataFile(chunk = msg)

def generate_chunks(filename, uuid, requestType):
    
    global TOTAL_CHUNKS
    cont = 0

    textToAnonymize = open(filename + ".txt", "r")

    while True:
        data = textToAnonymize.read(CHUNK_SIZE)

        if not data:
            textToAnonymize.close()
            break
        
        cont += CHUNK_SIZE
        TOTAL_CHUNKS = cont

        yield make_message(data, uuid, requestType)

def sendRequestForText(stub, filename, uuidClient, requestType):
    
    responses = stub.GetText(pb2.Request(uuidClient = uuidClient, type = requestType))

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
    
    responses = stub.GetItems(pb2.Request(uuidClient = uuidClient, type = requestType))

    if requestType == "anonymize":
        with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt", "w") as AnonymizerItemsResults:
            for response in responses:
                AnonymizerItemsResults.write('{' + f' "operator": "{response.operator}", "entity_type": "{response.entity_type}", "start": {response.start}, "end": {response.end}, "text": "{response.text}" ' + '}\n')

        print("{}-anonymize-items.txt created".format(filename))
        time.sleep(1)

    else:
        #print("IMPLEMENT!! SIA CLIENT CHE SERVER")
        with open(PATH_ANONYMIZER_RESULTS + filename + "-deanonymize-items.txt", "w") as DeanonymizerItemsResults:
            for response in responses:
                DeanonymizerItemsResults.write('{' + f' "start": {response.start}, "end": {response.end}, "operator": "{response.operator}", "text": "{response.text}", "entity_type": "NUMBER" ' + '}\n')

        print("{}-deanonymize-items.txt created\n".format(filename))
        time.sleep(1)

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
        res = input("Do you want reset the configuration? [Y/N] ").upper()

        if res == "Y":
            os.remove(configFile)
    
    print("\n{} Operator config (press Q for exit)\n".format(configType))
    
    while True:
        entity_type = input("Entity: ").upper()

        # QUITTING
        if entity_type == "Q" or entity_type == "QUIT":
            print("Quitting config..")
            break

        # NOT EXISTS
        if entity_type.upper() not in SUPPORTED_ENTITIES:
            print("CONFIG: entity '{}' not exits\n".format(entity_type))
            continue
                
        # CHECK FOR DUPLICATES
        check = check_duplicate(entity_type, configFile) 

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

def sendRequestAnonymize(stub, filename, config):

    # sending original text to anonymize
    chunk_iterator = generate_chunks(PATH_FILES + filename, 0, "anonymize")
    print("\nFROM CLIENT: sending original text...")
    response = stub.sendFile(chunk_iterator)
    uuidClient = response.uuidClient

    if response.chunks == TOTAL_CHUNKS:
        print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

        # sending analyzer results
        chunk_iterator = generate_chunks(PATH_ANALYZER_RESULTS + filename + "-results", uuidClient, "anonymize")
        print("FROM CLIENT: sending analyzer results...")
        response = stub.SendRecognizerResults(chunk_iterator)
        
        if response.chunks == TOTAL_CHUNKS:
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


def presidio_anonymizer_start(ip_address, port):

    try:
        with grpc.insecure_channel(ip_address + ':' + port) as channel:
            
            print("CONNECTING TO {}:{}".format(ip_address, port))
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
                        read_configuration(CONFIG_FILE)
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
    except:
        print("GENERIC EXCEPTION! (FIX THIS ERROR)")   

### STOP ANONYMIZER SECTION

def sendRequestDeanonymize(stub, filename):

    # sending anonymized text (UUID = 0 INSIGNIFICANT)
    chunk_iterator = generate_chunks(PATH_ANONYMIZER_RESULTS + filename + "-anonymized", 0, "deanonymize")
    print("\nFROM CLIENT: sending anonymized text...")
    response = stub.sendFile(chunk_iterator)
    uuidClient = response.uuidClient

    if response.chunks == TOTAL_CHUNKS:
        print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

        # sending items results
        chunk_iterator = generate_chunks(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items", uuidClient, "deanonymize")
        print("FROM CLIENT: sending items...")
        response = stub.SendRecognizerResults(chunk_iterator)

        if response.chunks == TOTAL_CHUNKS:
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


def presidio_deanonymizer_start(ip_address, port):
    
    try:
        with grpc.insecure_channel(ip_address + ':' + port) as channel:
            
            print("Connecting to {}:{}".format(ip_address, port))
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
                        read_configuration(CONFIG_FILE_DE)
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
    except:
        print("GENERIC EXCEPTION! (FIX THIS ERROR, DEANONYMIZATION)")


if __name__ == "__main__":

    while True:
        print(":::::::::::::::::: PRESIDIO ANONYMIZER (data loader) ::::::::::::::::::\n")
        print("1) Anonymize")
        print("2) Deanonymize")
        print("3) Quit")

        command = int(input("\nCommand: "))

        if command == 1:

            ip_address = input("\nIP ADDRESS: ")
            port = input("SERVER PORT: ")
            presidio_anonymizer_start(ip_address, port)

        elif command == 2:

            ip_address = input("\nIP ADDRESS: ")
            port = input("SERVER PORT: ")
            presidio_deanonymizer_start(ip_address, port)

        elif command == 3:
            print("\nQuitting..")
            time.sleep(1)
            break
        else:
            print("\nCommand not valid!\n") 
            time.sleep(1)   