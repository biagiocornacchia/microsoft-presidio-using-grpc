import grpc 
from proto import service_anon_pb2_grpc as pb2_grpc
from proto import service_anon_pb2 as pb2

from presidio_anonymizer import DeanonymizeEngine
from presidio_anonymizer.entities.engine import AnonymizerResult, OperatorConfig

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities.engine import RecognizerResult, OperatorConfig

from concurrent import futures
import uuid
import json
import os

PATH_TEMP = "anonymizer-temp/"

TOTAL_CHUNKS = 0
CHUNK_SIZE = 1024*1024 # 1MB

def test_deanonymizer(uuidClient):

    # CONFIG FILE DEVE ESSERE OBBLIGATORIO

    try:
        textToDeanonymize = open(PATH_TEMP + uuidClient + ".txt", "r")
    except IOError:
        print("[+] File text not exits")
        return -1

    try: 
        AnonymizerResults = open(PATH_TEMP + uuidClient + "-results.txt", "r") # items
    except IOError:
        print("[+] File recognizer results not exits")
        return -1

    res = []
    for line in AnonymizerResults:
        data = json.loads(line)
        
        if data["operator"] == "encrypt":
            res.append(AnonymizerResult.from_json(json.loads('{' + f' "start":{data["start"]}, "end":{data["end"]}, "entity_type": "{data["entity_type"]}" ' + '}')))


    AnonymizerResults.close()

    #################################################################
    # COSTRUISCO LISTA OPERATORS CONFIG (SE IMPOSTATA)

    config_file = 0

    try:
        config_file = open(PATH_TEMP + uuidClient + "-config.txt", "r")
    except IOError:
        print("[+] No config file found (using default config)")


    # controlla se è vuoto (strip rimuove gli spazi all'unizio e alla fine)
    if config_file:
        cstring = config_file.readline().strip()

        if cstring:
            for line in config_file:    
                cstring += " , " + line.strip()

        #print(cstring)
        result = json.loads('{' + cstring + ' }')
        #print(result)

        for elem in result:
            #print(elem)
            str_conf = result.get(elem)
            #print(str_conf)
            str_conf = str_conf.replace("'", "\"")
            #print(OperatorConfig.from_json(json.loads(str_conf)))
            result.update({elem : OperatorConfig.from_json(json.loads(str_conf))})

        #print(result)
        config_file.close()

    #############################################################

    engine = DeanonymizeEngine()

    result = engine.deanonymize(
        text=textToDeanonymize.read(),
        entities=res,
        operators=result
    )

    with open(PATH_TEMP + uuidClient + "-deanonymized.txt", "w") as fileDeanonymized:
        fileDeanonymized.write(result.text)

    with open(PATH_TEMP + uuidClient + "-items.txt", "w") as fileItemsAnonymized:
        for obj in result.items:
            fileItemsAnonymized.write('{' + f' "operator": "{obj.operator}", "entity_type": "{obj.entity_type}", "start": {obj.start}, "end": {obj.end}, "text": "{obj.text}" ' + '}\n')

    textToDeanonymize.close()
    return result


def make_message(msg):
    return pb2.DataFile(chunk = msg)

def test_anonymizer(uuidClient):
    
    # COSTRUISCO LA LISTA DEI RECOGNIZERS
    # SISTEMARE QUANDO IL FILE NON ESISTE!!!!

    try:
        textToAnonymize = open(PATH_TEMP + uuidClient + ".txt", "r")
    except IOError:
        print("[+] File text not exits")
        return -1

    try: 
        recognizerResults = open(PATH_TEMP + uuidClient + "-results.txt", "r")
    except IOError:
        print("[+] File recognizer results not exits")
        return -1

    res = []
    for line in recognizerResults:
        #print(RecognizerResult.from_json(json.loads(line)))
        res.append(RecognizerResult.from_json(json.loads(line)))

    recognizerResults.close()

    #################################################################
    # COSTRUISCO LISTA OPERATORS CONFIG (SE IMPOSTATA)
    config_file = 0

    try:
        config_file = open(PATH_TEMP + uuidClient + "-config.txt", "r")
    except IOError:
        print("[+] No config file found (using default config)")


    # controlla se è vuoto (strip rimuove gli spazi all'unizio e alla fine)
    if config_file:
        cstring = config_file.readline().strip()

        if cstring:
            for line in config_file:    
                cstring += " , " + line.strip()

        #print(cstring)
        result = json.loads('{' + cstring + ' }')
        #print(result)

        for elem in result:
            #print(elem)
            str_conf = result.get(elem)
            #print(str_conf)
            str_conf = str_conf.replace("'", "\"")
            #print(OperatorConfig.from_json(json.loads(str_conf)))
            result.update({elem : OperatorConfig.from_json(json.loads(str_conf))})

        #print(result)
        config_file.close()

    #############################################################

    engine = AnonymizerEngine()

    if config_file:
        result = engine.anonymize(
            text=textToAnonymize.read(),
            analyzer_results= res,
            operators=result
        )
    
    else:
        result = engine.anonymize(
            text=textToAnonymize.read(),
            analyzer_results= res
        )

    with open(PATH_TEMP + uuidClient + "-anonymized.txt", "w") as fileAnonymized:
            fileAnonymized.write(result.text)

    with open(PATH_TEMP + uuidClient + "-items.txt", "w") as fileItemsAnonymized:
            for obj in result.items:
                fileItemsAnonymized.write('{' + f' "operator": "{obj.operator}", "entity_type": "{obj.entity_type}", "start": {obj.start}, "end": {obj.end}, "text": "{obj.text}" ' + '}\n')

    textToAnonymize.close()

    return result

class AnonymizerEntity(pb2_grpc.AnonymizerEntityServicer):

    def sendFile(self, request_iterator, context):

        uuidClient = str(uuid.uuid1())
        print ("\n[+] UUID for the client: {}".format(uuidClient))
        print("[+] Receiving a new file...")

        TOTAL_CHUNKS = 0

        with open(PATH_TEMP + uuidClient + ".txt", "a") as f:
            for request in request_iterator:
                TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
                f.write(request.chunk)

        print("[+] File received")
            
        return pb2.FileAck(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)

    def SendRecognizerResult(self, request_iterator, context):

        TOTAL_CHUNKS = 0

        for request in request_iterator:

            if TOTAL_CHUNKS == 0:
                uuidClient = request.uuidClient
                print ("[+] UUID client: {}".format(uuidClient))
                print("[+] Receiving a recognizer results file...")

                f = open(PATH_TEMP + uuidClient + "-results.txt", "a")
            
            #print(request)
            TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
            f.write(request.chunk)

        f.close()
        print("[+] File received")
            
        return pb2.FileAck(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)

    def sendConfig(self, request, context):

        uuidClient = request.uuidClient
        print ("[+] UUID client: {}".format(uuidClient))
        print("[+] Receiving a config file...")

        with open(PATH_TEMP + uuidClient + "-config.txt", "w") as config_file:
            config_file.write(request.operators)

        print("[+] File received")

        return pb2.FileAck(chunks = -1, uuidClient = uuidClient)
    
    def GetText(self, request, context):

        uuidClient = request.uuidClient
        print ("[+] UUID client: {}".format(uuidClient))
        
        if request.type == "anonymize":
            print("[+] Receiving a request for anonymization...")        
            
            ################################################
            results = test_anonymizer(uuidClient)

            #print(results)

            if results:
                print("[+] Anonymized!\n")
                print(results.text)

                global TOTAL_CHUNKS
                cont = 0

                text = open(PATH_TEMP + uuidClient + "-anonymized.txt", "r")

                while True:
                    data = text.read(CHUNK_SIZE)

                    if not data:
                        text.close()
                        break
                    
                    cont += CHUNK_SIZE
                    TOTAL_CHUNKS = cont

                    yield make_message(data)

                text.close()

            else:
                print("[+] Error anonymization")
                yield pb2.DataFile(chunk = "-1")

            #####################################################
        else:
            print("[+] Receiving a request for deanonymization...")

            results = test_deanonymizer(uuidClient)

            #print(results)

            if results:
                print("[+] Deanonymized!\n")
                print(results.text)

                #global TOTAL_CHUNKS
                cont = 0

                text = open(PATH_TEMP + uuidClient + "-deanonymized.txt", "r")

                while True:
                    data = text.read(CHUNK_SIZE)

                    if not data:
                        text.close()
                        break
                    
                    cont += CHUNK_SIZE
                    TOTAL_CHUNKS = cont

                    yield make_message(data)

                text.close()

            else:
                print("[+] Error deanonymization")
                yield pb2.DataFile(chunk = "-1")

    def GetItems(self, request, context):
        
        uuidClient = request.uuidClient
        print ("\n[+] UUID client: {}".format(uuidClient))
        print("[+] Receiving a request for items anonymized...")

        itemsList = []
        with open(PATH_TEMP + uuidClient + "-items.txt", "r") as itemsFile:
            for line in itemsFile:
                itemsList.append(json.loads(line))

        for item in itemsList:
            yield pb2.Item(operator = item["operator"], entity_type = item["entity_type"], start = item["start"], end = item["end"], text = item["text"])
        
        print("[+] DONE!\n")
        
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

def run_server(port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnonymizerEntityServicer_to_server(AnonymizerEntity(), server)
    server.add_insecure_port('[::]:' + port)
    server.start()
    print("Listening on port {}\n".format(port))
    server.wait_for_termination()

if __name__ == "__main__":

    print("\n:::::::::::::::::: PRESIDIO ANONYMIZER (Server) ::::::::::::::::::\n")
    port = input("PORT: ")
    run_server(port)