FROM centos:7
RUN yum install -y gcc make
COPY rpms/* .
RUN yum localinstall -y libuv-1.27.0-1.el7.x86_64.rpm
RUN yum localinstall -y libwebsockets-3.0.1-2.el7.x86_64.rpm
RUN yum localinstall -y mosquitto-1.5.8-1.el7.x86_64.rpm
RUN yum localinstall -y mosquitto-devel-1.5.8-1.el7.x86_64.rpm
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
