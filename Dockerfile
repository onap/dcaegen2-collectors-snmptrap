# Use an official pypy runtime as a base image
FROM pypy:3.8

ENV INSROOT /opt/app
ENV APPUSER snmptrap
ENV APPDIR ${INSROOT}/${APPUSER}

# add group and user: ubuntu
RUN useradd -d ${APPDIR} ${APPUSER}
#
# add group and user: ubuntu - for when DCAE platform evolves and runs as NON-ROOT!!!
# RUN addgroup -g 1000 -S ${APPUSER} && \
#     adduser -u 1000 -S ${APPUSER} -G ${APPUSER}

WORKDIR ${APPDIR}

EXPOSE 162:6162/udp

# Copy the current directory contents into the container at ${APPDIR}
COPY ./snmptrap/ ./bin/
COPY ./etc/ ./etc/
COPY requirements.txt ./
#
# RUN pip install -r requirements.txt
RUN pip install --trusted-host files.pythonhosted.org -r requirements.txt

RUN mkdir -p /etc \
    && mkdir -p /etc/apt
RUN apt-get update -y && apt-get install -y jq bc vim

RUN mkdir -p ${APPDIR}/data \
 && mkdir -p ${APPDIR}/logs \
 && mkdir -p ${APPDIR}/tmp \
# && chown -R ${APPUSER}:${APPUSER} ${APPDIR} \
 && chmod a+w ${APPDIR}/data \
 && chmod a+w ${APPDIR}/logs \
 && chmod a+w ${APPDIR}/tmp \
 && chmod 500 ${APPDIR}/etc \
 && chmod 500 ${APPDIR}/bin/snmptrapd.sh \
 && chmod 500 ${APPDIR}/bin/scheduler.sh \
#  && ln -s /usr/bin/python3 /usr/bin/python \
 && rm ${APPDIR}/requirements.txt

# run everything from here on as $APPUSER, NOT ROOT!
#USER ${APPUSER}

# map logs directory to external volume
VOLUME ${APPDIR}/logs

# launch container
CMD ["./bin/snmptrapd.sh", "start"]
