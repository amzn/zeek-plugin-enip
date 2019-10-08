FROM      amazonlinux:latest
MAINTAINER https://github.com/amzn/

# Metadata
LABEL program=bro

# Specify program
ENV PROG zeek
# Specify source extension
ENV EXT tar.gz
# Specify Bro version to download and install (e.g. 3.0.0)
ENV VERS 3.0.0

# Install directory
ENV PREFIX /opt/bro
# Path should include prefix
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PREFIX/bin

# Install dependencies
RUN yum -y update
RUN yum -y install cronie epel-release  gcc gcc-c++ make libpcap-devel openssl-devel bind-devel zlib-devel cmake git perl libcurl-devel GeoIP-devel python-devel jemalloc-devel swig libpcap bind-libs zlib bash python libcurl gawk GeoIP jemalloc wget flex bison python-pip tar iproute procps-ng kernel-devel clang && yum clean all

# Compile and install Zeek
WORKDIR /tmp
RUN wget --no-check-certificate https://www.bro.org/downloads/$PROG-$VERS.$EXT && tar -xzf $PROG-$VERS.$EXT
WORKDIR /tmp/$PROG-$VERS
RUN ./configure  --prefix=$PREFIX --disable-python
RUN make
RUN make install

USER root
RUN pip install zkg
RUN zkg autoconfig
COPY [--chown=bro:bro] . /tmp/zeek-plugin-enip
WORKDIR /tmp/zeek-plugin-enip
RUN zkg install --force .
