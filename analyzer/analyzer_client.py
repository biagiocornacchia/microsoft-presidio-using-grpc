import grpc 
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2
from google.protobuf.json_format import MessageToJson, Parse

import json
import os

ENGINE_OPTIONS = [ "deny_list", "regex", "nlp_engine", "app_tracer", "log_decision_process", "default_score_threshold", "supported_languages" ]
ANALYZE_OPTIONS = ["language", "entities", "correlation_id", "score_threshold", "return_decision_process"]

PATH_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

class ClientEntity:

    def __init__(self, ip_address, port):

        self.ip_address = ip_address
        self.port = port
        self.channel = grpc.insecure_channel(ip_address + ':' + str(port))
        self.stub = pb2_grpc.AnalyzerEntityStub(self.channel)

        self.engine_curr_config = {}
        self.analyze_curr_config = {}

    def sendRequestAnalyze(self, filename):

        if not self.checkRequiredFiles(filename):
            return -1

        try:
            # sending original text to analyze
            chunk_iterator = generateChunks(filename)
            print("\nFROM CLIENT: sending original text...")
            response = self.stub.sendFileToAnalyze(chunk_iterator)

            if response.chunks == TOTAL_CHUNKS:
                print(f"FROM SERVER: file received correctly. UUID assigned: {response.uuidClient}")

                my_uuid = response.uuidClient

                # sending config options (if not empty)
                if self.engine_curr_config:
                    print("FROM CLIENT: sending AnalyzerEngine configuration...")  
                    
                    self.engine_curr_config['uuidClient'] = my_uuid
                    json_msg = json.dumps(self.engine_curr_config) 
                    response = self.stub.sendEngineOptions(Parse(json_msg, pb2.AnalyzerEngineOptions())) 

                if self.analyze_curr_config:
                    print("FROM CLIENT: sending analyze configuration...")
                    
                    self.analyze_curr_config['uuidClient'] = my_uuid
                    json_msg = json.dumps(self.analyze_curr_config) 
                    response = self.stub.sendOptions(Parse(json_msg, pb2.AnalyzeOptions())) 
                
                responses = self.stub.getAnalyzerResults(pb2.Request(uuidClient = my_uuid))
                print("FROM CLIENT: waiting for analyzer results...")
                
                with open(PATH_RESULTS + filename + "-results.txt", "w") as RecognizerResults:
                    for response in responses:
                        string = "{ " + f'"start": {response.start}, "end": {response.end}, "score": {response.score:.2f}, "entity_type": "{response.entity_type}", "analysis_explanation": "{response.analysis_explanation}"' + " }\n"
                        RecognizerResults.write(string)

                print(f"\n{filename}-results.txt created")
                return 1

            else:
                print("FROM SERVER: original text file not received correctly")
                return 0

        except grpc.RpcError as rpc_error:

            if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                print("Cannot connect to the server")
            else:
                print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")
            
            return -2

    def checkRequiredFiles(self, filename):

        # check text file
        if not os.path.exists(PATH_FILES + filename + ".txt"):
            print("ERROR: file text not found!")
            return False

        # check conf setup (AnalyzerEngine and Analyze params)
        if self.engine_curr_config:
            print("AnalyzerEngine configuration found!")
            # print(self.engine_curr_config)
        else:
            print("AnalyzerEngine configuration not found!")

        if self.analyze_curr_config:
            print("Analyze configuration found!")
            # print(self.analyze_curr_config)
        else:
            print("Analyze configuration not found!")

        return True

    def setupDenyList(self, supported_entities, valuesList):

        jsonString = "{ " + f'"supported_entity": {supported_entities}, "deny_list": {valuesList}' + " }"
        self.engine_curr_config["deny_list"] = jsonString.replace("'", "\"")
    
    def setupRegex(self, supported_entity, patterns, context):

        self.engine_curr_config['regex'] = "{ " + f'"supported_entity": "{supported_entity}", "pattern": {patterns}, "context": "{context}" ' + " }"

    def setupOptions(self, option, value, optionFile):
        
        if optionFile == "ANALYZE_OPTIONS":
            if option in ANALYZE_OPTIONS:
                self.analyze_curr_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        elif optionFile == "ENGINE_OPTIONS":
            if option in ENGINE_OPTIONS:
                self.engine_curr_config[option] = value
                return 1
            else:
                # invalid option name
                return -1
        else:
            # invalid optionFile 
            return -2

    def closeConnection(self):
        print("Disconnected from the server")
        self.channel.close()

# UTILITY FUNCTIONS

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

def createPatternInfo(num, nameList, regexList, scoreList):
    patterns = []
    
    for i in range(num):
        patterns.append("{ " + f"\'name_pattern\' : \'{nameList[i]}\', \'regex\' : \'{regexList[i]}\', \'score\' : {scoreList[i]}" + " }")

    return patterns