FROM itsafeaturemythic/python38_payload:0.0.7
RUN apt-get update && apt-get install -y osslsigncode openssl mingw-w64 wget --no-install-recommends
WORKDIR /tmp
RUN wget https://storage.googleapis.com/golang/go1.14.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
RUN ln -s /usr/local/go/bin/go /usr/bin/go