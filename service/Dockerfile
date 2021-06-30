FROM ubuntu:latest

RUN apt-get update -y 
RUN apt-get install -y python3-pip python-dev

COPY requirements.txt ./app/requirements.txt

WORKDIR /app

RUN pip3 install -r requirements.txt

COPY . /app

ENTRYPOINT [ "python3" ]

CMD [ "manage.py" ]

# docker build -t api .
# docker run -p 5000:5000 api
# docker login registry.gitlab.com/Ronho1/ddos-service -u [gitlab_username] -p [gitlab_token]
# docker build -t registry.gitlab.com/ronho1/ddos-service .
# docker push registry.gitlab.com/ronho1/ddos-service