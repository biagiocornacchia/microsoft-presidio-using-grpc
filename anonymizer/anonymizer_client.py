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

class ClientEntity:

    def __init__(self, ip_address, port):

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(ip_address + ':' + str(port))
        self.stub = pb2_grpc.AnonymizerEntityStub(self.channel)

    def readConfiguration(self, configFile):
        
        if os.path.exists(configFile):
            with open(configFile, "r") as ConfigFile:
                print("=============== CURRENT CONFIGURATION ===============\n")
                for line in ConfigFile:
                    lineConfig = json.loads(line)
                    print("Entity type: " + lineConfig['entity_type'])
                    print("Parameters: " + lineConfig['params'] + "\n")
            return True
        else:
            # config file not found
            return False

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
                print(f"FROM SERVER: file received correctly. UUID assigned: {uuidClient}")

                # sending analyzer results
                print("FROM CLIENT: sending analyzer results...")
                response = self.stub.sendRecognizerResults(readRecognizerResults(filename, uuidClient))

                if response.uuidClient == uuidClient:
                    print(f"FROM SERVER: analyzer results received correctly. UUID: {uuidClient}")

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
                                return 0 

                    except IOError:
                        print("FROM CLIENT: using a default configuration")
                    
                    print("\nWaiting for Microsoft Presidio Anonymizer...")
                    
                    if self.sendRequestForText(filename, uuidClient, "anonymize") == -1:
                        return -1

                    if self.sendRequestForItems(filename, uuidClient, "anonymize") == -1:
                        return -1
                    
                    return 1

                else:
                    print("FROM SERVER: analyzer results not received correctly.")
                    return 0
            else:
                print("FROM SERVER: original text file not received correctly")
                return 0

        except grpc.RpcError as rpc_error:

            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print("Cannot connect to the server\n")
            else:
                print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")

            return -2

    def sendRequestDeanonymize(self, filename):

        if not checkRequiredFiles(filename, "deanonymize"):
            return -1

        # sending anonymized text

        try:
            chunk_iterator = generateChunks(PATH_ANONYMIZER_RESULTS + filename)
            print("\nFROM CLIENT: sending anonymized text...")
            response = self.stub.sendFile(chunk_iterator)
            uuidClient = response.uuidClient

            if response.chunks == TOTAL_CHUNKS:
                print(f"FROM SERVER: file received correctly. UUID assigned: {uuidClient}")

                # sending items results
                print("FROM CLIENT: sending items...")
                response = self.stub.sendAnonymizedItems(readAnonymizedItems(filename, uuidClient))

                if response.uuidClient == uuidClient:
                    print(f"FROM SERVER: analyzer results received correctly. UUID: {uuidClient}")

                    # sending configuration file (IS REQUIRED!)
                    print("FROM CLIENT: sending file config...")

                    with open(CONFIG_FILE_DE, "r") as configFile:
                        response = self.stub.sendConfig(pb2.Config(uuidClient = uuidClient, operators = configFile.read(), type = "deanonymize"))

                        # ACK FROM SERVER: chunks is insignificant and uuidClient is used for acking
                        if response.chunks == -1 and response.uuidClient == uuidClient:  
                            print("FROM SERVER: configuration file received correctly")
                        else:  
                            print("FROM SERVER: configuration file not received correctly")
                            return 0  
                    
                    print("\nWaiting for Microsoft Presidio Anonymizer...")

                    if self.sendRequestForText(filename, uuidClient, "deanonymize") == -1:
                        return -1

                    if self.sendRequestForItems(filename, uuidClient, "deanonymize") == -1:
                        return -1

                    return 1

                else:
                    print("FROM SERVER: items results not received correctly.")
                    return 0

            else:
                print("FROM SERVER: anonymized text file not received correctly")
                return 0
            
        except grpc.RpcError as rpc_error:
            
            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print("Cannot connect to the server\n")
            else:
                print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")

            return -2

    def sendRequestForText(self, filename, uuidClient, requestType):
        # sends a request to get anonymized or deanonymized text
        responses = self.stub.getText(pb2.Request(uuidClient = uuidClient, type = requestType))

        if requestType == "anonymize":
            with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymized.txt", "w") as AnonymizerResults:
                for response in responses:
                    if response.chunk == -1:
                        # received a NAK
                        print("FROM SERVER: Error during anonymization")
                        return -1
                    else:
                        AnonymizerResults.write(response.chunk)
                        print(f"{filename}-anonymized.txt created")
                        return 1

        else:
            filename = filename.split("-")

            with open(PATH_ANONYMIZER_RESULTS + filename[0] + "-deanonymized.txt", "w") as DeanonymizerResults:
                for response in responses:
                    if response.chunk == -1:
                        # received a NAK
                        print("FROM SERVER: Error during deanonymization")
                        return -1
                    else:
                        DeanonymizerResults.write(response.chunk)
                        print(f"{filename[0]}-deanonymized.txt created")
                        return 1

    def sendRequestForItems(self, filename, uuidClient, requestType):
        # sends a request to get items generated during the anonymization or deanonymization
        responses = self.stub.getItems(pb2.Request(uuidClient = uuidClient, type = requestType))

        if requestType == "anonymize":
            with open(PATH_ANONYMIZER_RESULTS + filename + "-anonymized-items.txt", "w") as AnonymizerItemsResults:
                for response in responses:
                    AnonymizerItemsResults.write('{' + f' "operator": "{response.operator}", "entity_type": "{response.entity_type}", "start": {response.start}, "end": {response.end}, "text": "{response.text}" ' + '}\n')

            print(f"{filename}-anonymized-items.txt created")

        else:
            filename = filename.split("-")
            with open(PATH_ANONYMIZER_RESULTS + filename[0] + "-deanonymized-items.txt", "w") as DeanonymizerItemsResults:
                for response in responses:
                    DeanonymizerItemsResults.write('{' + f' "start": {response.start}, "end": {response.end}, "operator": "{response.operator}", "text": "{response.text}", "entity_type": "NUMBER" ' + '}\n')

            print(f"{filename[0]}-deanonymized-items.txt created")

    def closeConnection(self):
        print("Disconnected from the server")
        self.channel.close()

def readRecognizerResults(filename, uuidClient):
    # reads results file generated by the analyzer
    with open(PATH_ANALYZER_RESULTS + filename + "-results.txt", "r") as resultsFile:
        for line in resultsFile:
            item = json.loads(line)
            yield pb2.RecognizerResult(uuidClient = uuidClient, start = item['start'], end = item['end'], score = item['score'], entity_type = item['entity_type'])

def readAnonymizedItems(filename, uuidClient):
    # reads anonymized-items file generated by the anonymizer
    with open(PATH_ANONYMIZER_RESULTS + filename + "-items.txt", "r") as itemsFile:
        for line in itemsFile:
            item = json.loads(line)
            yield pb2.AnonymizedItem(uuidClient = uuidClient, start = item['start'], end = item['end'], entity_type = item['entity_type'], operator = item['operator'])

def checkRequiredFiles(filename, requestType):

    if requestType == "anonymize":
        
        # check on files
        if (not os.path.exists(PATH_FILES + filename + ".txt")) or (not os.path.exists(PATH_ANALYZER_RESULTS + filename + "-results.txt")):
            print("ERROR: file text or analyzer results not found!")
            return False

        # check configuration file
        configUp = 0
        if os.path.exists(CONFIG_FILE):
            configUp = 1

        if configUp == 0:
            print("Config file not found! (Using a default conf)")
        else:
            print("Config file found!")

        return True
                
    elif requestType == "deanonymize":

        # check on files
        if (not os.path.exists(PATH_ANONYMIZER_RESULTS + filename + ".txt")) or (not os.path.exists(PATH_ANONYMIZER_RESULTS + filename + "-items.txt")):
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
    options = []
    found = 0

    try:
        with open(configFile, 'r') as f:
            for line in f:
                if entity_type not in line:
                    options.append(line)
                else:
                    print(f"Duplicate found: {line}")
                    found = 1

        with open(configFile, 'w') as f:
            for optionElem in options:
                f.write(optionElem)

    except IOError:
        print("CONFIG: creating a new config file...")

    return found

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

# replaces the PII text entity with new string
def addReplace(entity_type, new_value):
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE)

    params = '{ ' + f'\\"type\\": \\"replace\\", \\"new_value\\": \\"{new_value}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found

# hashes the PII text entity
def addHash(entity_type, hash_type):
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE)

    params = '{ ' + f'\\"type\\": \\"hash\\", \\"hash_type\\": \\"{hash_type}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found

# anonymizes text to an encrypted form
def addEncrypt(entity_type, key):    
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE)

    params = '{ ' + f'\\"type\\": \\"encrypt\\", \\"key\\": \\"{key}\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found

# mask some or all given text entity PII with given character
def addMask(entity_type, masking_char, chars_to_mask, from_end):
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE)

    # from_end values: true or false only
    params = '{ ' + f'\\"type\\": \\"mask\\", \\"masking_char\\": \\"{masking_char}\\", \\"chars_to_mask\\": {int(chars_to_mask)}, \\"from_end\\": {from_end.lower()}' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found

# decrypt text to from its encrypted form
def addDecrypt(entity_type, key):
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE_DE)
    
    params = '{ ' + f'\\"type\\": \\"decrypt\\", \\"key\\": \\"{key}\\"' + ' }'

    with open(CONFIG_FILE_DE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found

# replaces the PII text entity with empty string
def addRedact(entity_type):
    # check for duplicate
    found = checkDuplicate(entity_type, CONFIG_FILE)

    params = '{ ' + f'\\"type\\": \\"redact\\"' + ' }'

    with open(CONFIG_FILE, 'a') as f:
        f.write("{ " + f'"entity_type" : "{entity_type}", "params" : "{params}"' + " }\n")

    return found