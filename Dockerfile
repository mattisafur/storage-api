FROM python:3-alpine

WORKDIR /app

COPY requirements.txt ./
RUN <<-EOF
apk add --no-cache postgresql-libs
apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev # build dependencies
pip install -r requirements.txt
apk --purge del .build-deps # remove build dependencies
EOF

COPY app.py data_utils.py database.py models.py ./

CMD [ "python", "app.py" ]

EXPOSE 5000