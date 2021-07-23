import grpc 
from proto import service_anon_pb2_grpc as pb2_grpc
from proto import service_anon_pb2 as pb2

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig

import json
import os
import time

SUPPORTED_ENTITIES = ['IBAN_CODE', 'US_PASSPORT', 'DATE_TIME', 'MEDICAL_LICENSE', 'CRYPTO', 'LOCATION', 'UK_NHS', 'US_SSN', 'CREDIT_CARD', 'US_BANK_NUMBER', 'US_ITIN', 'EMAIL_ADDRESS', 'PERSON', 'IP_ADDRESS', 'DOMAIN_NAME', 'PHONE_NUMBER', 'SG_NRIC_FIN', 'NRP', 'US_DRIVER_LICENSE']
ANONYMIZERS = ['hash', 'mask', 'redact', 'replace', 'custom', 'encrypt']

CONFIG_FILE = 'operatorConfig.txt'
CONFIG_FILE_DE = 'operatorDeConfig.txt'

PATH_ANONYMIZER_RESULTS = "../anonymizer-results/"
PATH_ANALYZER_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

def read_config():

    with open(CONFIG_FILE, "r") as ConfigFile:
        for line in ConfigFile:
            print(line.strip().replace("\"", ""))

def check_duplicate(entity_type):
    
    # print("Checking config for {}".format(entity_type))

    try:
        with open(CONFIG_FILE,'r') as f:
            for line in f:
                
                if entity_type in line:
                    print("\nConfig already exists: {}".format(line))
                    response = input("Do you want to reset your conf file? [Y/N]: ").upper()
                    
                    if response == "Y":
                        print("Resetting config file")
                        return 1
                    else:
                        print("Ignoring...")
                        return 0
    except IOError:
        print("Creating new config file...")

    return -1

def operator_(entity_type, params):

    with open(CONFIG_FILE,'a') as f:
        f.write(f'"{entity_type}" : "{params}"\n')
    
def anonymizer_options(anonymizer):
    # RITORNA UNA STRINGA in base al tipo di anonymizer
    # { "type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_end": true }  { "type": "redact" } { "type": "replace", "new_value": "NEW VALUE" }  
    # { "type": "encrypt", "key": "string" }  { "type": "hash", "hash_type": "string" }

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
        hash_type = input("Hash type: ")
        options = '{' + f"\'type\': \'{anonymizer}\', \'hash_type\': \'{hash_type}\'" + '}'

    elif anonymizer == "encrypt":
        
        print("** encrypt **")
        key = input("Key: ")
        options = '{' + f"\'type\': \'{anonymizer}\', \'key\': \'{key}\'" + '}'

    else:
        print("Invalid anonymizer")


    print("\nOPTIONS ({}): {}".format(anonymizer, options))
    return options

def start():

    while True:
        print("\n:::::::::::::::::: PRESIDIO ANONYMIZER (Client) ::::::::::::::::::\n")
        print("1) Setup a config file")
        print("2) Anonymize without config")
        print("3) Read the current config")
        print("4) Deanonymize")
        print("5) Quit")

        choose = int(input("\nChoose: "))

        if choose == 1:
            print("\nOperator Config (press q for exit)\n")

            # AnonymizerEngine.from_json(params)
            while True:
                entity_type = input("Entity: ").upper()

                # QUITTING
                if entity_type == "Q" or entity_type == "QUIT":
                    print("quitting config..")
                    break

                # NOT EXISTS
                if entity_type.upper() not in SUPPORTED_ENTITIES:
                    print("ENTITY NOT EXISTS\n")
                    continue
                
                # DUPLICATES
                check = check_duplicate(entity_type) 
                if check == 1:
                    # ask for a config reset
                    os.remove(CONFIG_FILE)

                elif check == 0:
                    # ask for a new entity type
                    continue

                # return -1

                anonymizer = input("Anonymizer: ").lower()

                if anonymizer not in ANONYMIZERS:
                    print("ANONYMIZER NOT EXISTS\n")
                    continue
                
                params = anonymizer_options(anonymizer)
                operator_(entity_type, params)

                print("{} -> {} - Config successfully updated.\n\n".format(entity_type, params))

            # ANONYMIZE
            response = input("\nStart the anonymization? [Y/N]: ").upper()

            ip_address = input("IP Server: ")
            port = input("PORT: ")

            if response == "Y":
                filename = input("Filename? ")
                anonymize(filename, 1, ip_address, port)
            else:
                print("Exting...")
        elif choose == 2: 

            print("\nAnonymize without config (DEFAULT CONFIG)")
            ip_address = input("IP Server: ")
            port = input("PORT: ")
            filename = input("Filename? ")
            anonymize(filename, 0, ip_address, port)
        elif choose == 3:
            
            read_config()

        elif choose == 4:
            
            print("Denonymize...")
            ip_address = input("IP Server: ")
            port = input("PORT: ")
            filename = input("Filename? ")
            deanonymize(filename, 1, ip_address, port)
        
        elif choose == 5:
            print("Quitting...")
            break
        else:
            print("Command not valid")

def make_message(msg, uuid, reqType):
    
    if uuid:
        return pb2.DataFile(uuidClient = uuid, chunk = msg, type = reqType)

    return pb2.DataFile(chunk = msg, type = reqType)

def generate_chunks(filename, uuid, reqType):
    
    global TOTAL_CHUNKS
    cont = 0

    try:
        textToAnonymize = open(filename + ".txt", "r")
    except IOError:
        print("ioERROR: file not exists")

    while True:
        data = textToAnonymize.read(CHUNK_SIZE)

        if not data:
            textToAnonymize.close()
            break
        
        cont += CHUNK_SIZE
        TOTAL_CHUNKS = cont

        yield make_message(data, uuid, reqType)

def send(stub, filename, config):

    # sends text to anonymizer and config for the anonymizer
    chunk_iterator = generate_chunks(PATH_FILES + filename, 0, "anonymize")
    response = stub.sendFile(chunk_iterator)
    uuidClient = response.uuidClient

    if response.chunks == TOTAL_CHUNKS:
        print("\nFile received correctly. UUID assigned: {}".format(uuidClient))

        chunk_iterator = generate_chunks(PATH_ANALYZER_RESULTS + filename + "-results", uuidClient, "anonymize")
        response = stub.SendRecognizerResult(chunk_iterator)
        #uuidClient = response.uuidClient

        if response.chunks == TOTAL_CHUNKS:
            print("\nRecognizer result file received correctly. UUID: {}".format(uuidClient))

            if config:
                print("\nSending file config...")
                with open(CONFIG_FILE, "r") as f:
                    response = stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = f.read(), type = "anonymize"))

                if response.chunks == -1 and response.uuidClient == uuidClient:  
                    # when receive an ack  
                    print("Config file received correctly.")    
            else:
                print("\nDefault config..nothing to send")

            print("\nWaiting for Microsoft Presidio Anonymizer...")
            sendRequestForText(stub, filename, uuidClient, "anonymize")
            sendRequestForItems(stub, filename, uuidClient)

        else:
            print("[+] Errore nell'invio del recognizer results")

    else:
        print("[+] Errore nell'invio del file di testo")
        # ERRORE NELL'INIVIO DEL FILE , ALZA UN ECCEZIONE(^)


def sendRequestForText(stub, filename, uuidClient, reqType):
    
    responses = stub.GetText(pb2.Request(uuidClient = uuidClient, type = reqType))

    if reqType == "anonymize":
        with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymized.txt", "w") as AnonymizerResults:
            for response in responses:
                if response.chunk == -1:
                    # received a NAK
                    print("Errore durante l'anonimizzazione")
                else:
                    AnonymizerResults.write(response.chunk)

        print("{}-anonymized.txt created\n".format(filename))
    else:
        with open(PATH_ANONYMIZER_RESULTS + filename + "-deanonymized.txt", "w") as DeanonymizerResults:
            for response in responses:
                if response.chunk == -1:
                    # received a NAK
                    print("Errore durante l'deanonimizzazione")
                else:
                    DeanonymizerResults.write(response.chunk)

        print("{}-deanonymized.txt created\n".format(filename))

def sendRequestForItems(stub, filename, uuidClient):
    
    responses = stub.GetItems(pb2.Request(uuidClient = uuidClient, type = "anonymize"))

    with open(PATH_ANONYMIZER_RESULTS + filename + "-items.txt", "w") as AnonymizerItemsResults:
        for response in responses:
            AnonymizerItemsResults.write('{' + f' "operator": "{response.operator}", "entity_type": "{response.entity_type}", "start": {response.start}, "end": {response.end}, "text": "{response.text}" ' + '}\n')

    print("{}-items.txt created\n".format(filename))
    time.sleep(2)

def anonymize(filename, config, ip_address, port):
    
    with grpc.insecure_channel(ip_address + ':' + port) as channel:
        stub = pb2_grpc.AnonymizerEntityStub(channel)
        send(stub, filename, config)  

def deanonymize(filename, config, ip_address, port):

    with grpc.insecure_channel(ip_address + ':' + port) as channel:
        stub = pb2_grpc.AnonymizerEntityStub(channel)

        chunk_iterator = generate_chunks(PATH_ANONYMIZER_RESULTS + filename + "-anonymized", 0, "deanonymize")
        response = stub.sendFile(chunk_iterator)
        uuidClient = response.uuidClient

        if response.chunks == TOTAL_CHUNKS:
            print("\nFile received correctly. UUID assigned: {}".format(uuidClient))

            chunk_iterator = generate_chunks(PATH_ANONYMIZER_RESULTS + filename + "-items", uuidClient, "deanonymize")
            response = stub.SendRecognizerResult(chunk_iterator)

            if response.chunks == TOTAL_CHUNKS:
                print("\nRecognizer result file received correctly. UUID: {}".format(uuidClient))

                if config:
                    print("\nSending file config (contains deanonymizers)...")
                    with open(CONFIG_FILE_DE, "r") as f:
                        response = stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = f.read(), type = "deanonymize"))

                    if response.chunks == -1 and response.uuidClient == uuidClient:  
                        # when receive an ack  
                        print("Config file received correctly.")    
                else:
                    print("\nDefault config..nothing to send")

                print("\nWaiting for Microsoft Presidio Deanonymizer...")
                sendRequestForText(stub, filename, uuidClient, "deanonymize")
                #sendRequestForItems(stub, filename, uuidClient)

            else:
                print("[+] Errore nell'invio del recognizer results")

        else:
            print("[+] Errore nell'invio del file di testo")
            # ERRORE NELL'INIVIO DEL FILE , ALZA UN ECCEZIONE(^)

if __name__ == "__main__":

    start()