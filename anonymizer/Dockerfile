FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip

RUN mkdir /anonymizer 
WORKDIR /anonymizer
COPY . /anonymizer
RUN chmod 777 /anonymizer/anonymizer-temp

RUN pip3 install -r requirements.txt

RUN useradd app
USER app

ENTRYPOINT [ "python3","-u","anonymizer_server.py" ]
