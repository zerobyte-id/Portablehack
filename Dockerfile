FROM golang:1.20.4-buster AS golangbuild
RUN apt-get update && apt-get install -y git gcc
WORKDIR /
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

FROM python:3.10.11-buster
COPY --from=golangbuild /go /go
RUN apt-get update && apt-get install -y g++ nmap
WORKDIR /app
COPY . /app/
ENV TZ=Asia/Jakarta
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN pip3 install --upgrade pip
RUN pip3 install requests
RUN pip3 install pytz
RUN pip3 install Flask
RUN pip3 install pandas
RUN pip3 install pymongo
RUN pip3 install redis
RUN pip3 install ipaddress
RUN pip3 install xmltodict
RUN pip3 install pyyaml