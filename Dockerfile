FROM ubuntu:latest

RUN apt-get update && apt install -y \
	automake \
	autoconf \
	libtool \
	software-properties-common \
	cmake \
	curl \
	git \
	build-essential \
	libssl-dev \
	libomp-dev \
	&& rm -rf /var/lib/apt/list/*

WORKDIR /root
# Download and extract openssl stable release
RUN curl -L https://github.com/openssl/openssl/releases/download/openssl-3.0.17/openssl-3.0.17.tar.gz -o openssl-3.0.17.tar.gz && \
	tar -xzf openssl-3.0.17.tar.gz && \
	rm openssl-3.0.17.tar.gz


# Compile openssl with change from Kunlun readme
WORKDIR /root/openssl-3.0.17
RUN sed -i '211s/\<static\>//' crypto/ec/curve25519.c
RUN ./Configure no-shared enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-comp --prefix=/usr/local/openssl
RUN make depend && make install


# Clone and compile Kunlun
WORKDIR /root
RUN git clone https://github.com/yuchen1024/Kunlun.git
RUN mkdir -p Kunlun/build
WORKDIR /root/Kunlun/build
RUN cmake .. && make

WORKDIR /root/Kunlun