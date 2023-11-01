FROM python:3.8-alpine

WORKDIR /app/
COPY ./ /app/
COPY ./.env /app/
RUN pip3 install -r requirements.txt
ENTRYPOINT [ "python3", "app.py" ]
