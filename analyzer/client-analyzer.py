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

ENGINE_OPTIONS = [ "deny_list", "regex", "nlp_engine", "app_tracer", "log_decision_process", "default_score_threshold", "supported_languages" ]
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

def others():
    clear()

    print("Available options: ")
    optionAvailable = ""
    for option in ENGINE_OPTIONS:
        if option != 'deny_list' and option != "regex" and option != "nlp_engine" and option != "app_tracer":
            optionAvailable += option.upper() + "  "

    print(optionAvailable + "\n")

    while True:

        option = input("Name: ").lower()

        if option == "q":
            print("Exting...")
            break

        if option in ENGINE_OPTIONS:

            if option == "log_decision_process":
                print("\nNOTE: possible values are 0 (False) or 1 (True)\n")

            value = input("Option value: ").lower()

            if option in ENGINE_CURR_CONFIG:

                response = input("This config already exists. Do you want to update it? [Y/N]: ").upper()
                if response == "Y":
                    
                    print("Updating...")
                    ENGINE_CURR_CONFIG.update({ option : value })
                    print("Option {} -> {}\n".format(option, value))

                elif response == "N":
                    print("Ignoring...")
                else:
                    print("Invalid command")
                    continue

            else:
                # adding a new option
                ENGINE_CURR_CONFIG[option] = value
                print("Option {} -> {}\n".format(option, value))

        else:
            print("Name option not valid!")
            continue

def PIIRecognition():
    clear()

    while True:
        print("1) Deny-list based PII recognition")
        print("2) Regex based PII recognition")
        print("3) Ad-hoc recognition")
        print("4) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            
            if 'deny_list' not in ENGINE_CURR_CONFIG:
                supported_entity = input("\nEntity: ").upper()
                
                if supported_entity == "Q":
                    print("Exiting...")
                    break
                
                print("\nNOTE: separate values with commas.\n")
                values = input("Values List: ")

                ENGINE_CURR_CONFIG['deny_list'] = "{ " + f'"supported_entity": "{supported_entity}", "deny_list": "{values}"' + " }"

            else:
                print("\nDeny-list configuration found: {}".format(ENGINE_CURR_CONFIG['deny_list']))
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    ENGINE_CURR_CONFIG.pop('deny_list')
                    print("Done")               

            exit()

        elif command == 2:
            
            if 'regex' not in ENGINE_CURR_CONFIG:
                supported_entity = input("\nEntity: ").upper()
                
                if supported_entity == "Q":
                    print("Exiting...")
                    break

                patterns = []
                while True:
                    
                    name_pattern = input("\nName Pattern: ")

                    if name_pattern == "q" or name_pattern == "Q":
                        print("Exiting...")
                        break

                    regex = input("Regex: ")
                    score = input("Score: ")
                    context = input("Contex words: ")

                    patterns.append("{ " + f"\'name_pattern\' : \'{name_pattern}\', \'regex\' : \'{regex}\', \'score\' : {score}" + " }")

                ENGINE_CURR_CONFIG['regex'] = "{ " + f'"supported_entity": "{supported_entity}", "pattern": {patterns}, "context": "{context}" ' + " }"

            else:
                print("\nRegex based configuration found: {}".format(ENGINE_CURR_CONFIG['regex']))
                response = input("\nDo you want to reset it? [Y/N]: ").upper()

                if response == "Y":
                    ENGINE_CURR_CONFIG.pop('regex')
                    print("Done")                 

            exit()

        elif command == 3:

            # ANALYZE_OPTIONS["ad_hoc_recognizers"]

            #"ad_hoc_recognizers":[
            #    {
            #    "name": "Zip code Recognizer",
            #    "supported_language": "en",
            #    "patterns": [
            #        {
            #        "name": "zip code (weak)", 
            #        "regex": "(\\b\\d{5}(?:\\-\\d{4})?\\b)", 
            #        "score": 0.01
            #        }
            #    ],
            #    "context": ["zip", "code"],
            #    "supported_entity":"ZIP"
            #    }
            #]

            pass

        elif command == 4:
            clear()
            break
        else:
            print("Command not valid\n")
            clear()

def setupEngine():
    clear()

    if ENGINE_CURR_CONFIG:
        print("\nENGINE CURRENT CONFIG FOUND: ")

        for elem in ENGINE_CURR_CONFIG:
            if elem != 'uuidClient':
                print(elem + " : " +  ENGINE_CURR_CONFIG[elem])

        print('\n')

    while True:
        print("1) PII recognition")
        print("2) Other options")
        print("3) Back")

        command = int(input("\nCommand: "))

        if command == 1:
            PIIRecognition()
            clear()

        elif command == 2:
            others()
            clear()

        elif command == 3:
            clear()
            break

        else:
            print("Command not valid\n")

def setupAnalyze():

    if ANALYZE_CURR_CONFIG:
        print("\nANALYZE CURRENT CONFIG FOUND: ")

        for elem in ANALYZE_CURR_CONFIG:
            if elem != 'uuidClient':
                print(elem + " : " +  ANALYZE_CURR_CONFIG[elem])

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

                response = input("This config already exists. Do you want to update it? [Y/N]: ").upper()
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
                string = "{ " + f'"start": {response.start}, "end": {response.end}, "score": {response.score:.2f}, "entity_type": "{response.entity_type}", "analysis_explanation": "{response.analysis_explanation}"' + " }\n"
                RecognizerResults.write(string)

        print("\n{}-results.txt created".format(filename))
        exit()

    else:
        print("FROM SERVER: original text file not received correctly")

def presidio_analyzer_start():

    try:
        with grpc.insecure_channel(IP_ADDRESS + ':' + PORT) as channel:
            
            print("SERVER INFO: {}:{}\n".format(IP_ADDRESS, PORT))
            stub = pb2_grpc.AnalyzerEntityStub(channel)

            while True:
                print("1) Setup AnalyzerEngine")
                print("2) Setup analyze params")
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
                        exit()
                        continue

                    # check conf setup (analyzeEngine and analyze params)
                    if ENGINE_CURR_CONFIG:
                        print("AnalyzeEngine configuration found!")
                        # print(ENGINE_CURR_CONFIG)
                    else:
                        print("AnalyzeEngine configuration not found!")

                    if ANALYZE_CURR_CONFIG:
                        print("Analyze configuration found!")
                        # print(ANALYZE_CURR_CONFIG)
                    else:
                        print("Analyze configuration not found!")

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
        print(":::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::\n")
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