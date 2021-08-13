import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_anonymizer import DeanonymizeEngine, AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, AnonymizerResult, OperatorConfig

from concurrent import futures
import uuid
import json
import os

PATH_TEMP = "anonymizer-temp/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

class AnonymizerEntityServicer(pb2_grpc.AnonymizerEntityServicer):

    def sendFile(self, request_iterator, context):

        uuidClient = str(uuid.uuid1())
        print (f"\n[+] UUID for the client: {uuidClient}")
        print("[+] Receiving a new file...")

        TOTAL_CHUNKS = 0

        with open(PATH_TEMP + uuidClient + ".txt", "a") as fileText:
            for request in request_iterator:
                TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
                fileText.write(request.chunk)

        print("[+] File text received")
            
        return pb2.FileAck(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)

    def sendRecognizerResults(self, request_iterator, context):
        
        uuidClient = 0

        for request in request_iterator:
            if uuidClient == 0:
                uuidClient = request.uuidClient
                print (f"[+] UUID client: {uuidClient}")
                print("[+] Receiving a recognizer results file...")
                fileText = open(PATH_TEMP + uuidClient + "-results.txt", "a")

            fileText.write("{ " + f'"start": {request.start}, "end": {request.end}, "score": {request.score}, "entity_type": "{request.entity_type}"' + " }\n")

        fileText.close()
        print("[+] File received")
            
        return pb2.FileAck(uuidClient = uuidClient)

    def sendAnonymizedItems(self, request_iterator, context):
        
        uuidClient = 0

        for request in request_iterator:
            if uuidClient == 0:
                uuidClient = request.uuidClient
                print (f"[+] UUID client: {uuidClient}")
                print("[+] Receiving anonymizer results file...")
                fileText = open(PATH_TEMP + uuidClient + "-results.txt", "a")

            fileText.write("{ " + f'"start": {request.start}, "end": {request.end}, "entity_type": "{request.entity_type}", "operator": "{request.operator}"' + " }\n")

        fileText.close()
        print("[+] File received")
            
        return pb2.FileAck(uuidClient = uuidClient)

    def sendConfig(self, request, context):

        uuidClient = request.uuidClient
        print (f"[+] UUID client: {uuidClient}")
        print("[+] Receiving a config file...")

        with open(PATH_TEMP + uuidClient + "-config.txt", "w") as configFile:
            configFile.write(request.operators)

        print("[+] Config file received")

        return pb2.FileAck(chunks = -1, uuidClient = uuidClient)
    
    def getText(self, request, context):

        uuidClient = request.uuidClient
        print (f"[+] UUID client: {uuidClient}")
        
        if request.type == "anonymize":
            print("[+] Receiving a request for anonymization...")        
            results = startAnonymization(uuidClient)
            filename = PATH_TEMP + uuidClient + "-anonymized.txt"

        elif request.type == "deanonymize":
            print("[+] Receiving a request for deanonymization...")
            results = startDeanonymization(uuidClient)
            filename = PATH_TEMP + uuidClient + "-deanonymized.txt"

        else:
            print("[+] Request type error")
        
        if results:
            print("[+] Done successfully!\n")
            print(results.text)

            global TOTAL_CHUNKS
            cont = 0

            with open(filename, "r") as textFile:
                while True:
                    data = textFile.read(CHUNK_SIZE)

                    if not data:
                        break
                    
                    cont += CHUNK_SIZE
                    TOTAL_CHUNKS = cont

                    yield makeMessage(data)
        else:
            # sends a NAK
            print("[+] Error during operation")
            yield pb2.DataFile(chunk = "-1")

    def getItems(self, request, context):
        
        uuidClient = request.uuidClient
        print (f"\n[+] UUID client: {uuidClient}")
        print("[+] Receiving a request for items anonymized...")

        itemsList = []
        with open(PATH_TEMP + uuidClient + "-items.txt", "r") as itemsFile:
            for line in itemsFile:
                itemsList.append(json.loads(line))

        for item in itemsList:
            yield pb2.Item(operator = item["operator"], entity_type = item["entity_type"], start = item["start"], end = item["end"], text = item["text"])
        
        print("[+] Operation completed!\n")
        
        # cleaning temp files
        if os.path.exists(PATH_TEMP + uuidClient + "-config.txt"):
            os.remove(PATH_TEMP + uuidClient + "-config.txt")

        if request.type == "anonymize":
            os.remove(PATH_TEMP + uuidClient + "-anonymized.txt")
        else:
            os.remove(PATH_TEMP + uuidClient + "-deanonymized.txt")

        os.remove(PATH_TEMP + uuidClient + ".txt")
        os.remove(PATH_TEMP + uuidClient + "-results.txt")
        os.remove(PATH_TEMP + uuidClient + "-items.txt")

def makeMessage(msg):
    return pb2.DataFile(chunk = msg)

def startAnonymization(uuidClient):
    
    # Building recognizers list made by analyzer engine
    # checking the necessary files

    try:
        textToAnonymize = open(PATH_TEMP + uuidClient + ".txt", "r")

    except IOError:
        print("[+] Original file text not exits")
        return -1

    recognizerResultsList = []

    try: 
        with open(PATH_TEMP + uuidClient + "-results.txt", "r") as recognizerResults:   
            for line in recognizerResults:
                recognizerResultsList.append(RecognizerResult.from_json(json.loads(line)))

    except IOError:
        print("[+] File recognizer results not exits")
        return -1

    # Building operators list to perform a particular anonymization (if exists a config file otherwise use a default configuration)
    configFile = 0

    try:
        configFile = open(PATH_TEMP + uuidClient + "-config.txt", "r")

    except IOError:
        print("[+] No config file found (using default config)")

    configResult = {}

    if configFile:
        
        for line in configFile:
            configStr = json.loads(line)
            #print(json.loads(configStr['params']))
            configResult[configStr['entity_type']] =  OperatorConfig.from_json(json.loads(configStr['params']))

        configFile.close()

    engine = AnonymizerEngine()

    if configFile:
        result = engine.anonymize(
            text=textToAnonymize.read(),
            analyzer_results= recognizerResultsList,
            operators=configResult
        )
    
    else:
        result = engine.anonymize(
            text=textToAnonymize.read(),
            analyzer_results= recognizerResultsList
        )

    with open(PATH_TEMP + uuidClient + "-anonymized.txt", "w") as fileAnonymized:
            fileAnonymized.write(result.text)

    with open(PATH_TEMP + uuidClient + "-items.txt", "w") as fileItemsAnonymized:
            for obj in result.items:
                fileItemsAnonymized.write('{' + f' "operator": "{obj.operator}", "entity_type": "{obj.entity_type}", "start": {obj.start}, "end": {obj.end}, "text": "{obj.text}" ' + '}\n')

    textToAnonymize.close()
    return result

def startDeanonymization(uuidClient):

    try:
        textToDeanonymize = open(PATH_TEMP + uuidClient + ".txt", "r")
    except IOError:
        print("[+] Anonymized file text not exits")
        return -1

    try: 
        with open(PATH_TEMP + uuidClient + "-results.txt", "r") as AnonymizerResults: # items
            anonymizerResultsList = []

            for line in AnonymizerResults:
                data = json.loads(line)
                
                if data["operator"] == "encrypt":
                    anonymizerResultsList.append(AnonymizerResult.from_json(json.loads('{' + f' "start":{data["start"]}, "end":{data["end"]}, "entity_type": "{data["entity_type"]}" ' + '}')))

    except IOError:
        print("[+] File recognizer results not exits")
        return -1

    # Building operators list to perform a particular deanonymization (config file is required!)
    configFile = 0

    try:
        configFile = open(PATH_TEMP + uuidClient + "-config.txt", "r")
    except IOError:
        print("[+] No config file found - Cannot complete the deanonymization!")
        return -1

    configResult = {}

    if configFile:
        for line in configFile:
            configStr = json.loads(line)
            configResult[configStr['entity_type']] =  OperatorConfig.from_json(json.loads(configStr['params']))

        configFile.close()

    engine = DeanonymizeEngine()

    result = engine.deanonymize(
        text=textToDeanonymize.read(),
        entities=anonymizerResultsList,
        operators=configResult
    )

    with open(PATH_TEMP + uuidClient + "-deanonymized.txt", "w") as fileDeanonymized:
        fileDeanonymized.write(result.text)

    with open(PATH_TEMP + uuidClient + "-items.txt", "w") as fileItemsAnonymized:
        for obj in result.items:
            fileItemsAnonymized.write('{' + f' "operator": "{obj.operator}", "entity_type": "{obj.entity_type}", "start": {obj.start}, "end": {obj.end}, "text": "{obj.text}" ' + '}\n')

    textToDeanonymize.close()
    return result

def runServer(port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnonymizerEntityServicer_to_server(AnonymizerEntityServicer(), server)
    server.add_insecure_port('[::]:' + str(port))
    server.start()
    print(f"Listening on port {port}\n")
    server.wait_for_termination()

if __name__ == "__main__":

    print(":::::::::::::::::: PRESIDIO ANONYMIZER (Server) ::::::::::::::::::\n")
    port = 8061 #input("PORT: ")
    runServer(port)