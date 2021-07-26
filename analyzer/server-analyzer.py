import grpc 
from proto import service_pb2_grpc as pb2_grpc
from proto import service_pb2 as pb2
from google.protobuf.json_format import MessageToJson, Parse

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

import pprint
import json
import os
import uuid
from concurrent import futures

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

PATH_TEMP = "analyzer-temp/"

class AnalyzerEntity(pb2_grpc.AnalyzerEntityServicer):

    def sendFileToAnalyze(self, request_iterator, context):

        # save chunks into a file
        # open a file and apply analyzer
        # call analyzer function made by me that read that file and returns a list of analyzer results

        uuidClient = str(uuid.uuid1())
        print("[+] UUID for the client: {}".format(uuidClient))
        print("[+] Receiving a new file...")
    
        TOTAL_CHUNKS = 0

        with open(PATH_TEMP + uuidClient + ".txt", "a") as f:
            for request in request_iterator:
                TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
                f.write(request.chunk)

        print("[+] File received")
            
        return pb2.FileAck(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)
    
    def sendEngineOptions(self, request, context):

        print("[+] Receiving a new configuration file (engine)...")
        #print(request)

        with open(PATH_TEMP + request.uuidClient + "-engineConfig.txt", "w") as engineConfig:
            # create json file
            engineConfig.write(MessageToJson(request, preserving_proto_field_name=True))

        print("[+] File received")        

        return pb2.Ack(uuidClient = request.uuidClient)

    def sendOptions(self, request, context):

        print("[+] Receiving a new configuration file...")
        #print(request)

        with open(PATH_TEMP + request.uuidClient + "-analyzeConfig.txt", "w") as analyzeConfig:
            # create json file
            analyzeConfig.write(MessageToJson(request, preserving_proto_field_name=True))

        print("[+] File received") 

        return pb2.Ack(uuidClient = request.uuidClient)

    def GetAnalyzerResults(self, request, context):
        
        print("\n[+] Preparing for Presidio Analyzer")
        print("[+] Searching for {}".format(request.uuidClient))

        try:
            with open(PATH_TEMP + request.uuidClient + ".txt", "r") as fileText:
                results = getResult(request.uuidClient, fileText.read())
            
            os.remove(PATH_TEMP + request.uuidClient + ".txt")

        except IOError:
            print("[+] File not exists!")

        for res in results:
            yield pb2.AnalyzerResults(entity_type = res.entity_type, start = res.start, end = res.end, score = res.score, analysis_explanation = str(res.analysis_explanation))

def getEngineOptions(uuid, ENGINE_OPTIONS):
    
    try:
        with open(PATH_TEMP + uuid + "-engineConfig.txt", "r") as engineConfig:
            options = json.loads(engineConfig.read())
            #print(options)

            # -----------------------------------------------------------------------------------------------------------------------------------

            for elem in options:
                if elem == "supported_languages":

                    opt = options[elem].lower()
                    ENGINE_OPTIONS.update({ elem : opt.split(",") })

                elif elem == "regex":

                    # Define the regex pattern in a Presidio `Pattern` object:
                    # numbers_pattern = Pattern(name="numbers_pattern",regex="\d+", score = 0.5)
                    # Define the recognizer with one or more patterns
                    # number_recognizer = PatternRecognizer(supported_entity="NUMBER", patterns = [numbers_pattern]. context = [list words])

                    json_options = json.loads(options[elem])

                    patterns = []
                    for patternElem in json_options['pattern']:
                        Elem = patternElem.replace("'", "\"")
                        Elem = Elem.replace("\\", "\\\\")
                        Elem = json.loads(Elem)
                        patterns.append(Pattern(name = Elem['name_pattern'], regex = Elem['regex'], score = Elem['score']))

                    if json_options['context'] == "":
                        json_options['context'] = None
                    else:
                        json_options['context'].strip(",")

                    custom_recognizer = PatternRecognizer(supported_entity = json_options['supported_entity'], patterns = patterns, context = json_options['context'])
                    
                    print("[+] Regex recognizer found")
                    registry = RecognizerRegistry()
                    registry.load_predefined_recognizers()
                    registry.add_recognizer(custom_recognizer)

                    ENGINE_OPTIONS.update({ 'registry' : registry })

                elif elem == "denyList":
                    
                    # DENY LIST
                    # titles_recognizer = PatternRecognizer(supported_entity="TITLE", deny_list=["Mr.","Mrs.","Miss"])
                    
                    json_options = json.loads(options[elem])
                    deny_list = json_options['deny_list'].strip(",")

                    #print(json_options)
                    #print(deny_list)

                    custom_recognizer = PatternRecognizer(supported_entity = json_options['supported_entity'], deny_list = deny_list)                    
                    
                    print("[+] Deny List recognizer found")
                    registry = RecognizerRegistry()
                    registry.load_predefined_recognizers()
                    registry.add_recognizer(custom_recognizer)

                    ENGINE_OPTIONS.update({ 'registry' : registry })

                else:
                    ENGINE_OPTIONS.update({ elem : options[elem] })
        
        os.remove(PATH_TEMP + uuid + "-engineConfig.txt")

    except IOError:
        print("[+] Engine config not exists")

def getAnalyzeOptions(uuid, ANALYZE_OPTIONS):

    try:
        with open(PATH_TEMP + uuid + "-analyzeConfig.txt", "r") as analyzeConfig:
            options = json.loads(analyzeConfig.read())
            #print(options)

            for elem in options:
                if elem == "entities":
                    opt = options[elem].upper()
                    ANALYZE_OPTIONS.update({ elem : opt.split(",") })
                else:
                    ANALYZE_OPTIONS.update({ elem : options[elem] })
        
        os.remove(PATH_TEMP + uuid + "-analyzeConfig.txt")

    except IOError:
        print("[+] Analyze config not exists!")   

def getResult(uuid, data):
    
    ENGINE_OPTIONS = { "registry": None, "regex": None, "deny_list": None, "nlp_engine": None, "app_tracer": None, "log_decision_process": 0, "default_score_threshold": 0, "supported_languages": None }
    ANALYZE_OPTIONS = { "language":  "en", "entities": None, "correlation_id": None, "score_threshold": 0, "return_decision_process": 0, "ad_hoc_recognizers": None}

    # check if engineConfig or analyzeConfig exist
    getEngineOptions(uuid, ENGINE_OPTIONS)
    getAnalyzeOptions(uuid, ANALYZE_OPTIONS)

    #print("\n")
    #print(ENGINE_OPTIONS)
    #print(ANALYZE_OPTIONS)
    #print("\n")

    # PERFORM
    analyzer = AnalyzerEngine(
                                registry = ENGINE_OPTIONS['registry'],
                                nlp_engine = ENGINE_OPTIONS['nlp_engine'], # !fix
                                app_tracer = ENGINE_OPTIONS['app_tracer'], # !fix
                                log_decision_process = int(ENGINE_OPTIONS['log_decision_process']), 
                                default_score_threshold = float(ENGINE_OPTIONS['default_score_threshold']),
                                supported_languages = ENGINE_OPTIONS['supported_languages'] # list of languages
    )
    results = analyzer.analyze(
                                data, 
                                language= ANALYZE_OPTIONS['language'], 
                                entities = ANALYZE_OPTIONS['entities'],
                                correlation_id = ANALYZE_OPTIONS['correlation_id'], 
                                score_threshold = float(ANALYZE_OPTIONS['score_threshold']), 
                                return_decision_process = int(ANALYZE_OPTIONS['return_decision_process']),
                                ad_hoc_recognizers = ANALYZE_OPTIONS['ad_hoc_recognizers'] # Array of objects (PatternRecognizer)
    )

    if int(ANALYZE_OPTIONS['return_decision_process']):
        for result in results:
            decision_process = result.analysis_explanation
            pp = pprint.PrettyPrinter()
            print("\nDecision process output:\n")
            pp.pprint(decision_process.__dict__)

    print("[+] Presidio Analyzer: DONE!\n")
    return results

def run_server(port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_AnalyzerEntityServicer_to_server(AnalyzerEntity(), server)
    server.add_insecure_port('[::]:' + port)
    server.start()
    print("Listening on port {}\n".format(port))
    server.wait_for_termination()

if __name__ == '__main__':
    
    print("\n:::::::::::::::::: PRESIDIO ANALYZER (Server) ::::::::::::::::::\n")
    port = input("PORT: ")
    run_server(port)