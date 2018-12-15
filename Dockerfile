FROM centos:7
RUN yum install -y gcc make
RUN yum install -y epel-release
RUN yum install -y mosquitto-devel
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

