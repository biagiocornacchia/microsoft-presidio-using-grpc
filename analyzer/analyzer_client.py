import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2
from google.protobuf.json_format import MessageToJson, Parse

import json
import os

ENGINE_OPTIONS = [ "deny_list", "regex", "nlp_engine", "app_tracer", "log_decision_process", "default_score_threshold", "supported_languages" ]
ANALYZE_OPTIONS = ["language", "entities", "correlation_id", "score_threshold", "return_decision_process"]

ENGINE_CURR_CONFIG = {}
ANALYZE_CURR_CONFIG = {}

PATH_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

class ClientEntity():

    def __init__(self, ip_address, port):

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(ip_address + ':' + str(port))
        self.stub = pb2_grpc.AnalyzerEntityStub(self.channel)

    def sendRequestAnalyze(self, filename):

        if not checkRequiredFiles(filename):
            return -1

        # sending original text to analyze
        chunk_iterator = generateChunks(filename)
        print("\nFROM CLIENT: sending original text...")
        response = self.stub.sendFileToAnalyze(chunk_iterator)

        if response.chunks == TOTAL_CHUNKS:
            print("FROM SERVER: file received correctly. UUID assigned: {}".format(response.uuidClient))

            my_uuid = response.uuidClient
            
            # sending config options (if not empty)
            if ENGINE_CURR_CONFIG:
                print("FROM CLIENT: sending Engine configuration...")  
                
                ENGINE_CURR_CONFIG['uuidClient'] = my_uuid
                json_msg = json.dumps(ENGINE_CURR_CONFIG) 
                response = self.stub.sendEngineOptions(Parse(json_msg, pb2.AnalyzerEngineOptions())) 

            if ANALYZE_CURR_CONFIG:
                print("FROM CLIENT: sending analyze configuration...")
                
                ANALYZE_CURR_CONFIG['uuidClient'] = my_uuid
                json_msg = json.dumps(ANALYZE_CURR_CONFIG) 
                response = self.stub.sendOptions(Parse(json_msg, pb2.AnalyzeOptions())) 
            
            responses = self.stub.GetAnalyzerResults(pb2.Request(uuidClient = my_uuid))
            print("FROM CLIENT: waiting for analyzer results...")
            
            with open(PATH_RESULTS + filename + "-results.txt", "w") as RecognizerResults:
                for response in responses:
                    string = "{ " + f'"start": {response.start}, "end": {response.end}, "score": {response.score:.2f}, "entity_type": "{response.entity_type}", "analysis_explanation": "{response.analysis_explanation}"' + " }\n"
                    RecognizerResults.write(string)

            print("\n{}-results.txt created".format(filename))

        else:
            print("FROM SERVER: original text file not received correctly")

    def setupDenyList(self, supported_entity, values):

        ENGINE_CURR_CONFIG["deny_list"] = "{ " + f'"supported_entity": "{supported_entity}", "deny_list": "{values}"' + " }"
    
    def setupRegex(self, supported_entity, patterns, context):

        ENGINE_CURR_CONFIG['regex'] = "{ " + f'"supported_entity": "{supported_entity}", "pattern": {patterns}, "context": "{context}" ' + " }"

    def setupOptions(self, option, value, configFile, update):

        if update:
            configFile.update({ option : value })
        else:
            configFile[option] = value

    def closeConnection(self):
        print("Disconnected from the server")
        self.channel.close()

# UTILITY FUNCTIONS

def checkRequiredFiles(filename):

    # check text file
    if not os.path.exists(PATH_FILES + filename + ".txt"):
        print("ERROR: file text not found!")
        return False

    # check conf setup (AnalyzerEngine and Analyze params)
    if ENGINE_CURR_CONFIG:
        print("AnalyzerEngine configuration found!")
        # print(ENGINE_CURR_CONFIG)
    else:
        print("AnalyzerEngine configuration not found!")

    if ANALYZE_CURR_CONFIG:
        print("Analyze configuration found!")
        # print(ANALYZE_CURR_CONFIG)
    else:
        print("Analyze configuration not found!")

    return True

def clear():

    if name == "nt":
        _ = system("cls")
    else:
        _ = system("clear")

def makeMessage(msg):
    return pb2.DataFile(chunk = msg)

def generateChunks(filename):

    global TOTAL_CHUNKS
    cont = 0

    with open(PATH_FILES + filename + ".txt", "r") as textToAnalyze:
        while True:
            data = textToAnalyze.read(CHUNK_SIZE)

            if not data:
                break
            
            cont += CHUNK_SIZE
            TOTAL_CHUNKS = cont

            yield makeMessage(data)