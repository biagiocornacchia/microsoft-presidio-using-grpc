import grpc 
from proto import service_pb2_grpc as pb2_grpc
from proto import service_pb2 as pb2

from presidio_analyzer import AnalyzerEngine

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

        f = open(PATH_TEMP + uuidClient + ".txt", "a")
        for request in request_iterator:
            TOTAL_CHUNKS = TOTAL_CHUNKS + CHUNK_SIZE
            f.write(request.chunk)
        f.close()

        print("[+] File received")
            
        return pb2.FileAck(chunks = TOTAL_CHUNKS, uuidClient = uuidClient)

    def GetAnalyzerResults(self, request, context):
        
        print("[+] Preparing for Presidio Analyzer")
        print("[+] Searching for {}".format(request.uuidClient))

        try:
            f = open(PATH_TEMP + request.uuidClient + ".txt", "r")
            results = getResult(f.read())
            f.close()
            os.remove(PATH_TEMP + request.uuidClient + ".txt")
        except:
            print("[+] File not exists!")

        for res in results:
            yield pb2.AnalyzerResults(entity_type = res.entity_type, start = res.start, end = res.end, score = res.score)


def getResult(data):
    
    analyzer = AnalyzerEngine()
    results = analyzer.analyze(data, language='en')
    print("[+] Presidio Analyzer: DONE!\n\n")

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