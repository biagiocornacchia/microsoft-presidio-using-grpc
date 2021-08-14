import grpc 
from google.protobuf.json_format import MessageToJson, Parse
from proto import model_pb2_grpc as pb2_grpc
from proto import model_pb2 as pb2

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

import json
import os
import uuid
from concurrent import futures
#import pprint

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

PATH_TEMP = "analyzer-temp/"

class AnalyzerEntityServicer(pb2_grpc.AnalyzerEntityServicer):

    def sendFileToAnalyze(self, request_iterator, context):

        # generate a unique id for the client
        uuidClient = str(uuid.uuid1())
        print(f"[+] UUID for the client: {uuidClient}")
        print("[+] Receiving a new file...")
    
        TOTAL_CHUNKS = 0

        with open(PATH_TEMP + uuidClient + ".txt", "a") as fileText:
            for request in request_iterator:
                TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
                fileText.write(request.chunk)

        print("[+] File received")
            
        return pb2.Ack(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)
    
    def sendEngineOptions(self, request, context):

        print("[+] Receiving an engine configuration file...")

        with open(PATH_TEMP + request.uuidClient + "-engineConfig.json", "w") as engineConfig:
            engineConfig.write(MessageToJson(request, preserving_proto_field_name=True))

        print("[+] File received")        

        return pb2.Ack(uuidClient = request.uuidClient)

    def sendOptions(self, request, context):

        print("[+] Receiving an analyzer configuration file...")

        with open(PATH_TEMP + request.uuidClient + "-analyzeConfig.json", "w") as analyzeConfig:
            analyzeConfig.write(MessageToJson(request, preserving_proto_field_name=True))

        print("[+] File received") 

        return pb2.Ack(uuidClient = request.uuidClient)

    def getAnalyzerResults(self, request, context):
        
        print("\n[+] Preparing for Presidio Analyzer")
        print(f"[+] Searching for {request.uuidClient}")
        
        results = []

        try:
            with open(PATH_TEMP + request.uuidClient + ".txt", "r") as fileText:
                results = getResult(request.uuidClient, fileText.read())
            
            os.remove(PATH_TEMP + request.uuidClient + ".txt")

        except IOError:
            print("[+] File not exists!")
            # context.set_code(5)

        for res in results:
            yield pb2.AnalyzerResults(entity_type = res.entity_type, start = res.start, end = res.end, score = res.score, analysis_explanation = str(res.analysis_explanation).replace("\"", "'"))


def getResult(uuid, fileText):
    
    # Default options
    ENGINE_OPTIONS = { "registry": None, "regex": None, "deny_list": None, "nlp_engine": None, "app_tracer": None, "log_decision_process": 0, "default_score_threshold": 0, "supported_languages": None }
    ANALYZE_OPTIONS = { "language":  "en", "entities": None, "correlation_id": None, "score_threshold": 0, "return_decision_process": 0, "ad_hoc_recognizers": None }

    # check if engine configuration or analyze() configuration exist
    getEngineOptions(uuid, ENGINE_OPTIONS)
    getAnalyzeOptions(uuid, ANALYZE_OPTIONS)

    analyzer = AnalyzerEngine(
                                registry = ENGINE_OPTIONS['registry'],
                                nlp_engine = ENGINE_OPTIONS['nlp_engine'], # default value
                                app_tracer = ENGINE_OPTIONS['app_tracer'], # default value
                                log_decision_process = int(ENGINE_OPTIONS['log_decision_process']), 
                                default_score_threshold = float(ENGINE_OPTIONS['default_score_threshold']),
                                supported_languages = ENGINE_OPTIONS['supported_languages'] # list of specified languages
    )
    results = analyzer.analyze(
                                fileText, 
                                language= ANALYZE_OPTIONS['language'], 
                                entities = ANALYZE_OPTIONS['entities'],
                                correlation_id = ANALYZE_OPTIONS['correlation_id'], 
                                score_threshold = float(ANALYZE_OPTIONS['score_threshold']), 
                                return_decision_process = int(ANALYZE_OPTIONS['return_decision_process']),
                                ad_hoc_recognizers = ANALYZE_OPTIONS['ad_hoc_recognizers'] # array of objects (PatternRecognizer)
    )

    #if int(ANALYZE_OPTIONS['return_decision_process']):
    #    for result in results:
    #        decision_process = result.analysis_explanation
    #        pp = pprint.PrettyPrinter()
    #        print("\nDecision process output:\n")
    #        pp.pprint(decision_process.__dict__)

    print("[+] Presidio Analyzer: DONE!\n")
    return results

def getEngineOptions(uuid, ENGINE_OPTIONS):
    
    try:
        with open(PATH_TEMP + uuid + "-engineConfig.json", "r") as engineConfig:

            options = json.loads(engineConfig.read())
            custom_recognizers = []

            for elem in options:
                if elem == "supported_languages":

                    languages = options[elem].lower()
                    ENGINE_OPTIONS.update({ elem : languages.split(",") })

                elif elem == "regex":
                    print("[+] Regex recognizer found")

                    regex_info = json.loads(options[elem])

                    patterns = []
                    for info in regex_info['pattern']:
                        Elem = info.replace("'", "\"").replace("\\", "\\\\")
                        Elem = json.loads(Elem)
                        patterns.append(Pattern(name = Elem['name_pattern'], regex = Elem['regex'], score = Elem['score']))

                    context_list = None
                    
                    if regex_info['context'] != "":
                        context_list = regex_info['context'].split(",")

                    custom_recognizers.append(PatternRecognizer(supported_entity = regex_info['supported_entity'], patterns = patterns, context = context_list))

                elif elem == "deny_list":
                
                    print("[+] Deny List recognizer found")
                
                    deny_info = json.loads(options[elem])

                    deny_lists = []
                    supported_entities = []

                    for entity in deny_info['supported_entity']:
                        supported_entities.append(entity)

                    for tokens in deny_info['deny_list']:
                        deny_lists.append(tokens.split(","))

                    print("\n")
                    for i in range(len(supported_entities)):
                        print(f"{i} | SUPPORTED_ENTITY: {supported_entities[i]} | DENY_LIST: {deny_lists[i]}")
                        custom_recognizers.append(PatternRecognizer(supported_entity = supported_entities[i], deny_list = deny_lists[i]))                 
                    print("\n")
                    
                else:
                    ENGINE_OPTIONS.update({ elem : options[elem] })
            
        # add new recognizers to the list of predefined recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        for recognizer in custom_recognizers:
            registry.add_recognizer(recognizer)

        ENGINE_OPTIONS.update({ 'registry' : registry })
        
        os.remove(PATH_TEMP + uuid + "-engineConfig.json")

    except IOError:
        print("[+] Engine config not exists")

def getAnalyzeOptions(uuid, ANALYZE_OPTIONS):

    try:
        with open(PATH_TEMP + uuid + "-analyzeConfig.json", "r") as analyzeConfig:
            options = json.loads(analyzeConfig.read())

            for elem in options:

                if elem == "entities":
                    entities = options[elem].upper()

                    if entities != "NONE":
                        ANALYZE_OPTIONS.update({ elem : entities.split(",") })

                else:
                    ANALYZE_OPTIONS.update({ elem : options[elem] })
        
        os.remove(PATH_TEMP + uuid + "-analyzeConfig.json")

    except IOError:
        print("[+] Analyze config not exists!")   

def run_server():
    port = 8061
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnalyzerEntityServicer_to_server(AnalyzerEntityServicer(), server)
    server.add_insecure_port('[::]:' + str(port))
    server.start()
    print(f"Listening on port {port}\n")
    server.wait_for_termination()

if __name__ == '__main__':
    print(":::::::::::::::::: PRESIDIO ANALYZER (Server) ::::::::::::::::::\n")
    #port = input("PORT: ")
    run_server()