FROM centos:7
RUN yum install -y gcc make
COPY rpms/ rpms/
RUN yum localinstall -y rpms/libuv-1.44.2-1.el7.x86_64.rpm
RUN yum localinstall -y rpms/libwebsockets-3.0.1-2.el7.x86_64.rpm
RUN yum localinstall -y rpms/mosquitto-1.6.10-1.el7.x86_64.rpm
RUN yum localinstall -y rpms/mosquitto-devel-1.6.10-1.el7.x86_64.rpm
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
