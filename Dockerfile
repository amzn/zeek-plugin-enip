FROM      public.ecr.aws/amazonlinux/amazonlinux:latest
MAINTAINER https://github.com/amzn/

# Metadata
LABEL program=zeek

# Specify program
ENV PROG zeek
# Specify source extension
ENV EXT tar.gz
# Specify Zeek version to download and install (e.g. 3.0.0)
ENV VERS 3.2.4

# Specify Cmake version
ENV CMAKEVERSMAIN 3.10
ENV CMAKEVERSSUB .0

# Install directory
ENV PREFIX /opt/zeek
# Path should include prefix
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PREFIX/bin

# Install dependencies
RUN yum -y update
RUN yum -y install cronie epel-release  gcc gcc-c++ make libpcap-devel openssl-devel bind-devel zlib-devel git perl libcurl-devel GeoIP-devel python-devel jemalloc-devel swig libpcap bind-libs zlib bash python3 libcurl gawk GeoIP jemalloc wget flex bison python3-pip tar iproute procps-ng kernel-devel clang gdb && yum clean all

# Zeek 3.1.0 needs Cmake 3.0 or higher
WORKDIR /tmp
RUN wget https://cmake.org/files/v$CMAKEVERSMAIN/cmake-$CMAKEVERSMAIN$CMAKEVERSSUB.tar.gz
RUN tar -xvzf cmake-$CMAKEVERSMAIN$CMAKEVERSSUB.tar.gz
WORKDIR /tmp/cmake-$CMAKEVERSMAIN$CMAKEVERSSUB
RUN /tmp/cmake-$CMAKEVERSMAIN$CMAKEVERSSUB/bootstrap
RUN make -j$((`nproc`-1))
RUN make install

# Compile and install Zeek
WORKDIR /tmp
RUN wget https://old.zeek.org/downloads/$PROG-$VERS.$EXT && tar -xzf $PROG-$VERS.$EXT
WORKDIR /tmp/$PROG-$VERS
RUN ./configure  --build-type=RelWithDebInfo --prefix=$PREFIX --disable-python
RUN make -j$((`nproc`-1))
RUN make install

USER root
RUN pip3 install zkg
RUN zkg autoconfig
COPY [--chown=bro:bro] . /tmp/zeek-plugin-enip
WORKDIR /tmp/zeek-plugin-enip
RUN zkg install --force .
