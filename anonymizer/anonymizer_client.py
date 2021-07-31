import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig

import json
import os

SUPPORTED_ENTITIES = ['IBAN_CODE', 'US_PASSPORT', 'DATE_TIME', 'MEDICAL_LICENSE', 'CRYPTO', 'LOCATION', 'UK_NHS', 'US_SSN', 'CREDIT_CARD', 'US_BANK_NUMBER', 'US_ITIN', 'EMAIL_ADDRESS', 'PERSON', 'IP_ADDRESS', 'DOMAIN_NAME', 'PHONE_NUMBER', 'SG_NRIC_FIN', 'NRP', 'US_DRIVER_LICENSE']
ANONYMIZERS = ['hash', 'mask', 'redact', 'replace', 'custom', 'encrypt', 'decrypt']

CONFIG_FILE = 'config/operatorConfigAnonymizer.txt'
CONFIG_FILE_DE = 'config/operatorConfigDeanonymizer.txt'

PATH_ANONYMIZER_RESULTS = "../anonymizer-results/"
PATH_ANALYZER_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

class ClientEntity():

    def __init__(self, ip_address, port):

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(ip_address + ':' + str(port))
        self.stub = pb2_grpc.AnonymizerEntityStub(self.channel)

    def readConfiguration(self, configFile):
        
        if os.path.exists(configFile):
            with open(configFile, "r") as ConfigFile:
                print("\n")
                for line in ConfigFile:
                    print(line.strip().replace("\"", ""))
        else:
            print("Config file not found!")

    def addOperator(self, entity_type, params, configFile):
    
        with open(configFile, 'a') as f:
            f.write(f'"{entity_type}" : "{params}"\n')

    def sendRequestAnonymize(self, filename):

        if not checkRequiredFiles(filename, "anonymize"):
            return -1

        # sending original text to anonymize
        try:
            chunk_iterator = generateChunks(PATH_FILES + filename)
            print("\nFROM CLIENT: sending original text...")
            response = self.stub.sendFile(chunk_iterator)
            uuidClient = response.uuidClient

            if response.chunks == TOTAL_CHUNKS:
                print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

                # sending analyzer results
                print("FROM CLIENT: sending analyzer results...")
                response = self.stub.sendRecognizerResults(ReadRecognizerResults(filename, uuidClient))

                if response.uuidClient == uuidClient:
                    print("FROM SERVER: analyzer results received correctly. UUID: {}".format(uuidClient))

                    # sending configuration file
                    try:
                        print("FROM CLIENT: searching for a file config...")

                        with open(CONFIG_FILE, "r") as configFile:
                            print("FROM CLIENT: sending file config...")
                            response = self.stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = configFile.read(), type = "anonymize"))

                            # ACK FROM SERVER: chunks is insignificant and uuidClient is used for ack
                            if response.chunks == -1 and response.uuidClient == uuidClient:  
                                print("FROM SERVER: configuration file received correctly")
                            else:  
                                print("FROM SERVER: configuration file not received correctly")  

                    except IOError:
                        print("FROM CLIENT: using a default configuration")
                    
                    print("\nWaiting for Microsoft Presidio Anonymizer...")
                    self.sendRequestForText(filename, uuidClient, "anonymize")
                    self.sendRequestForItems(filename, uuidClient, "anonymize")

                else:
                    print("FROM SERVER: analyzer results not received correctly.")

            else:
                print("FROM SERVER: original text file not received correctly")

        except grpc.RpcError as rpc_error:

            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print("Cannot connect to the server\n")
            else:
                print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")

    def sendRequestDeanonymize(self, filename):

        if not checkRequiredFiles(filename, "deanonymize"):
            return -1

        # sending anonymized text

        try:
            chunk_iterator = generateChunks(PATH_ANONYMIZER_RESULTS + filename + "-anonymized")
            print("\nFROM CLIENT: sending anonymized text...")
            response = self.stub.sendFile(chunk_iterator)
            uuidClient = response.uuidClient

            if response.chunks == TOTAL_CHUNKS:
                print("FROM SERVER: file received correctly. UUID assigned: {}".format(uuidClient))

                # sending items results
                print("FROM CLIENT: sending items...")
                response = self.stub.sendAnonymizedItems(ReadAnonymizedItems(filename, uuidClient))

                if response.uuidClient == uuidClient:
                    print("FROM SERVER: analyzer results received correctly. UUID: {}".format(uuidClient))

                    # sending configuration file (IS REQUIRED!)
                    print("FROM CLIENT: sending file config...")

                    with open(CONFIG_FILE_DE, "r") as configFile:
                        response = self.stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = configFile.read(), type = "deanonymize"))

                        # ACK FROM SERVER: chunks is insignificant and uuidClient is used for acking
                        if response.chunks == -1 and response.uuidClient == uuidClient:  
                            print("FROM SERVER: configuration file received correctly")
                        else:  
                            print("FROM SERVER: configuration file not received correctly")  
                    
                    print("\nWaiting for Microsoft Presidio Anonymizer...")
                    self.sendRequestForText(filename, uuidClient, "deanonymize")
                    self.sendRequestForItems(filename, uuidClient, "deanonymize")

                else:
                    print("FROM SERVER: items results not received correctly.")

            else:
                print("FROM SERVER: anonymized text file not received correctly")
            
        except grpc.RpcError as rpc_error:
            
            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print("Cannot connect to the server\n")
            else:
                print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")

    def sendRequestForText(self, filename, uuidClient, requestType):
        # sends a request to get anonymized or deanonymized text
        responses = self.stub.getText(pb2.Request(uuidClient = uuidClient, type = requestType))

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

    def sendRequestForItems(self, filename, uuidClient, requestType):
        # sends a request to get items generated during the anonymization or deanonymization
        responses = self.stub.getItems(pb2.Request(uuidClient = uuidClient, type = requestType))

        if requestType == "anonymize":
            with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt", "w") as AnonymizerItemsResults:
                for response in responses:
                    AnonymizerItemsResults.write('{' + f' "operator": "{response.operator}", "entity_type": "{response.entity_type}", "start": {response.start}, "end": {response.end}, "text": "{response.text}" ' + '}\n')

            print("{}-anonymize-items.txt created".format(filename))

        else:
            with open(PATH_ANONYMIZER_RESULTS + filename + "-deanonymize-items.txt", "w") as DeanonymizerItemsResults:
                for response in responses:
                    DeanonymizerItemsResults.write('{' + f' "start": {response.start}, "end": {response.end}, "operator": "{response.operator}", "text": "{response.text}", "entity_type": "NUMBER" ' + '}\n')

            print("{}-deanonymize-items.txt created".format(filename))

    def closeConnection(self):
        print("Disconnected from the server")
        self.channel.close()

def ReadRecognizerResults(filename, uuidClient):
    # reads results file generated by the analyzer
    with open(PATH_ANALYZER_RESULTS + filename + "-results.txt", "r") as resultsFile:
        for line in resultsFile:
            item = json.loads(line)
            yield pb2.RecognizerResult(uuidClient = uuidClient, start = item['start'], end = item['end'], score = item['score'], entity_type = item['entity_type'])

def ReadAnonymizedItems(filename, uuidClient):
    # reads anonymize-items file generated by the anonymizer
    with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt", "r") as itemsFile:
        for line in itemsFile:
            item = json.loads(line)
            yield pb2.AnonymizedItem(uuidClient = uuidClient, start = item['start'], end = item['end'], entity_type = item['entity_type'], operator = item['operator'])

def anonymizerOptions(anonymizer, configType):
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
        # DEANONYMIZER SUPPORTS ONLY 'DECRYPT' ANONYMIZER
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

    return options

def checkRequiredFiles(filename, requestType):

    if requestType == "anonymize":
        
        # check on files
        if not os.path.exists(PATH_FILES + filename + ".txt") and not os.path.exists(PATH_ANALYZER_RESULTS + filename + "-results.txt"):
            print("ERROR: file text or analyzer results not found!")
            return False

        # check configuration file
        configUp = 0
        if os.path.exists(CONFIG_FILE):
            configUp = 1

        if configUp == 0:
            print("Config file not found! (Using a default conf)")
            enableConfig = input("Do you want to use a default configuration? [Y/N] ").upper()

            if enableConfig == "Y":
                print("Anonymize with a default configuration")
            else:
                print("Setup a config file")
        else:
            print("Config file found!")

        return True
                
    elif requestType == "deanonymize":

        # check on files
        if not os.path.exists(PATH_ANONYMIZER_RESULTS + filename + "-anonymized.txt") and not os.path.exists(PATH_ANONYMIZER_RESULTS + filename + "-anonymize-items.txt"):
            print("ERROR: file text anonymized or anonymized items not found!")
            return False

        # check configuration file (for deanonymizatoin it is REQUIRED!)
        if os.path.exists(CONFIG_FILE_DE) == 0:
            print("Config file not found!")
            print("You have to setup a config file before deanonymize")
            return False
        else:
            print("Config file found!")

        return True

    else:
        print("Request type not valid!")

def checkDuplicate(entity_type, configFile):
    # checks if a config option is already setted
    try:
        with open(configFile, 'r') as f:
            for line in f:
                if entity_type in line:
                    print("\nCONFIG: config entry type already exists: {}".format(line))
                    response = input("Do you want to reset your conf file? [Y/N]: ").upper()
                    
                    if response == "Y":
                        #print("CONFIG: resetting config file")
                        return 1
                    else:
                        #print("CONFIG: ignoring...")
                        return 0
    except IOError:
        print("CONFIG: creating a new config file...")

    return -1

def makeMessage(msg):
    return pb2.DataFile(chunk = msg)

def generateChunks(filename):
    
    global TOTAL_CHUNKS
    cont = 0

    textFile = open(filename + ".txt", "r")

    while True:
        data = textFile.read(CHUNK_SIZE)

        if not data:
            textFile.close()
            break
        
        cont += CHUNK_SIZE
        TOTAL_CHUNKS = cont

        yield makeMessage(data)
