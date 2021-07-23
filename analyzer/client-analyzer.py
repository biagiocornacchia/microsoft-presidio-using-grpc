import grpc 
from proto import service_pb2_grpc as pb2_grpc
from proto import service_pb2 as pb2

import json
import os

PATH_RESULTS = "../analyzer-results/"
PATH_FILES = "../files/"

CHUNK_SIZE = 1024*1024 # 1MB
TOTAL_CHUNKS = 0

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

def send(stub, filename):

    chunk_iterator = generate_chunks(filename)
    response = stub.sendFileToAnalyze(chunk_iterator)

    if response.chunks == TOTAL_CHUNKS:
        print("File received correctly. UUID assigned: {}".format(response.uuidClient))
        responses = stub.GetAnalyzerResults(pb2.Request(uuidClient = response.uuidClient))
        print("Waiting for analyzer results...")
        
    with open(PATH_RESULTS + filename + "-results.txt", "w") as RecognizerResults:
        for response in responses:
            string = "{ " + f'"start": {response.start}, "end": {response.end}, "score": {response.score:.2f}, "entity_type": "{response.entity_type}"' + " }\n"
            RecognizerResults.write(string)

    print("{}-results.txt created\n".format(filename))


def run(filename, ip_address, port):
    
    try: 
        with grpc.insecure_channel(ip_address + ':' + port) as channel:
            stub = pb2_grpc.AnalyzerEntityStub(channel)
            print("\nCONNECTED TO {}:{}".format(ip_address, port))
            send(stub, filename)

    except grpc.RpcError as rpc_error:
        if rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
            print("CANNOT CONNECT TO {}:{}\n".format(ip_address, port))
        else:
            print("Received unknown RPC error: code={} message={}\n".format(rpc_error.code(), rpc_error.details()))

if __name__ == '__main__':

    try:
        print("\n:::::::::::::::::: PRESIDIO ANALYZER (data loader) ::::::::::::::::::\n")
        ip_address = input("IP: ")
        port = input("PORT: ")

        while True:
            filename = input("filename: ")
            print("\nSearching for {}".format(filename))
            
            if os.path.exists(PATH_FILES + filename + ".txt"):
                run(filename, ip_address, port)
            else:
                print("The file '{}.txt' does not exist".format(filename))

    except KeyboardInterrupt:
        print("Exiting...")