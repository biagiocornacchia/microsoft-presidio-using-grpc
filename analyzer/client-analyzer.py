import grpc 
from proto import service_pb2_grpc as pb2_grpc
from proto import service_pb2 as pb2
from google.protobuf.json_format import MessageToJson, Parse

import json
import time
import os
from os import system, name

IP_ADDRESS = "NULL"
PORT = "-1"

ENGINE_OPTIONS = [ "registry", "nlp_engine", "app_tracer", "log_decision_process", "default_score_threshold", "supported_languages" ]
ANALYZE_OPTIONS = ["language", "entities", "correlation_id", "score_threshold", "return_decision_process", "ad_hoc_recognizers" ]
ENGINE_CURR_CONFIG = {}
ANALYZE_CURR_CONFIG = {}

PATH_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

# UTILITY FUNCTIONS

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

def make_message(msg):
    return pb2.DataFile(chunk = msg)

def generate_chunks(filename):
    
    global TOTAL_CHUNKS
    cont = 0

    with open(PATH_FILES + filename + ".txt", "r") as textToAnalyze:
        while True:
            data = textToAnalyze.read(CHUNK_SIZE)

            if not data:
                break
            
            cont += CHUNK_SIZE
            TOTAL_CHUNKS = cont

            yield make_message(data)

#########

def setupEngine():

    # DENY LIST
    # titles_recognizer = PatternRecognizer(supported_entity="TITLE", deny_list=["Mr.","Mrs.","Miss"])

    # REGEXXX
    # numbers_pattern = Pattern(name="numbers_pattern",regex="\d+", score = 0.5)
    # number_recognizer = PatternRecognizer(supported_entity="NUMBER", patterns = [numbers_pattern])
    clear()

    while True:

        print("1) Deny-list based PII recognition")
        print("2) Regex based PII recognition")
        print("3) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            
            supported_entity = input("\nEntity: ")
            
            if supported_entity == "q" or supported_entity == "Q":
                print("Exiting...")
                break

            deny_list = []
            
            while True:

                value = input("Value: ")

                if value == "q" or value == "Q":
                    print("Exiting...")
                    break

                deny_list.append(value)

            print("\nEntity: {}".format(supported_entity))
            print("Deny list: ")
            for elem in deny_list:
                print(elem)

            exit()

        elif command == 2:
            
            supported_entity = input("\nEntity: ")
            
            if supported_entity == "q" or supported_entity == "Q":
                print("Exiting...")
                break

            patterns = []
            
            while True:

                value = input("Value: ")

                if value == "q" or value == "Q":
                    print("Exiting...")
                    break

                patterns.append(value)

            print("\nEntity: {}".format(supported_entity))
            print("Patterns list: ")

            for elem in patterns:
                print(elem)

            exit()

        elif command == 3:
            clear()
            break
        else:
            print("Command not valid\n")

def setupAnalyze():

    print("\nAvailable options: ")
    optionAvailable = ""
    for option in ANALYZE_OPTIONS:
        optionAvailable += option.upper() + "  "

    print(optionAvailable + "\n")

    while True:

        option = input("Name: ").lower()

        if option == "q":
            print("Exting...")
            break

        if option in ANALYZE_OPTIONS:

            if option == "entities":
                print("\nNOTE: separate entities with commas. For example: PERSON,LOCATION,IP_ADDRESS..\n")

            if option == "return_decision_process":
                print("\nNOTE: possible values are 0 (False) or 1 (True)\n")

            value = input("Option value: ").lower()

            if option in ANALYZE_CURR_CONFIG:

                response = input("This config exist. Do you want update it? [Y/N]: ").upper()
                if response == "Y":
                    
                    print("Updating...")
                    ANALYZE_CURR_CONFIG.update({ option : value })
                    print("Option {} -> {}\n".format(option, value))

                elif response == "N":
                    print("Ignoring...")
                else:
                    print("Invalid command")
                    continue

            else:
                # adding a new option
                ANALYZE_CURR_CONFIG[option] = value
                print("Option {} -> {}\n".format(option, value))

        else:
            print("Name option not valid!")
            continue


def sendRequestAnalyze(stub, filename, EngineConfig, AnalyzeConfig):

    # sending original text to analyze
    chunk_iterator = generate_chunks(filename)
    print("\nFROM CLIENT: sending original text...")
    response = stub.sendFileToAnalyze(chunk_iterator)

    if response.chunks == TOTAL_CHUNKS:
        print("FROM SERVER: file received correctly. UUID assigned: {}".format(response.uuidClient))

        my_uuid = response.uuidClient
        
        # sending config options (if not empty)

        if EngineConfig:
            print("FROM CLIENT: sending Engine configuration...")  
            
            ENGINE_CURR_CONFIG['uuidClient'] = my_uuid
            json_msg = json.dumps(ENGINE_CURR_CONFIG) 
            response = stub.sendEngineOptions(Parse(json_msg, pb2.AnalyzerEngineOptions())) 

        if AnalyzeConfig:
            print("FROM CLIENT: sending analyze configuration...")
            
            ANALYZE_CURR_CONFIG['uuidClient'] = my_uuid
            json_msg = json.dumps(ANALYZE_CURR_CONFIG) 
            response = stub.sendOptions(Parse(json_msg, pb2.AnalyzeOptions())) 
        
        responses = stub.GetAnalyzerResults(pb2.Request(uuidClient = my_uuid))
        print("FROM CLIENT: waiting for analyzer results...")
        
        with open(PATH_RESULTS + filename + "-results.txt", "w") as RecognizerResults:
            for response in responses:
                # print(response)
                string = "{ " + f'"start": {response.start}, "end": {response.end}, "score": {response.score:.2f}, "entity_type": "{response.entity_type}"' + " }\n"
                RecognizerResults.write(string)

        print("{}-results.txt created\n".format(filename))
        exit()

    else:
        print("FROM SERVER: original text file not received correctly")

def presidio_analyzer_start():

    try:
        with grpc.insecure_channel(IP_ADDRESS + ':' + PORT) as channel:
            
            print("SERVER INFO: {}:{}".format(IP_ADDRESS, PORT))
            stub = pb2_grpc.AnalyzerEntityStub(channel)

            while True:
                print("\n1) Setup AnalyzerEngine")
                print("2) Setup analyze() function")
                print("3) Analyze")
                print("4) Back")

                command = int(input("\nCommand: "))
        
                if command == 1:

                    setupEngine()
                    clear()

                elif command == 2:
                    
                    setupAnalyze()
                    clear()

                elif command == 3:

                    filename = input("\nFilename: ")
                    print("\nSearching for {}".format(filename))

                    # check text file
                    filesExist = 0
                    if os.path.exists(PATH_FILES + filename + ".txt"):
                        filesExist = 1

                    if filesExist == 0:
                        print("ERROR: file text not found!")
                        continue

                    # check conf setup (analyzeEngine and analyze() function)
                    if ENGINE_CURR_CONFIG:
                        print("AnalyzeEngine configuration found!")
                        print(ENGINE_CURR_CONFIG)
                    else:
                        print("Current engine config not found!")

                    if ANALYZE_CURR_CONFIG:
                        print("Analyze() configuration found!")
                        print(ANALYZE_CURR_CONFIG)
                    else:
                        print("Current analyze() config not found!")

                    sendRequestAnalyze(stub, filename, ENGINE_CURR_CONFIG, ANALYZE_CURR_CONFIG)

                elif command == 4:
                    clear()
                    break
                else:
                    print("\nCommand not valid!")
                    
    except grpc.RpcError as rpc_error:
        if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
            print("Cannot connect to the server\n")
        else:
            print(f"Received unknown RPC error: code={rpc_error.code()} message={rpc_error.details()}\n")   

if __name__ == "__main__":
    clear()

    while True:
        print("\n:::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::\n")
        print("1) Analyzer")
        print("2) Server configuration")
        print("3) Quit")

        command = int(input("\nCommand: "))

        if command == 1:
            clear()
            
            if IP_ADDRESS == "NULL" or PORT == "-1":
                print("No server info found!")
                exit()
            else:
                presidio_analyzer_start()  
            
        elif command == 2:

            IP_ADDRESS = input("\nIP ADDRESS: ")
            PORT = input("SERVER PORT: ")
            exit()

        elif command == 3:
            print("\nQuitting..")
            time.sleep(1)
            break

        else:
            print("\nCommand not valid!\n") 
            clear()
            #time.sleep(1)  