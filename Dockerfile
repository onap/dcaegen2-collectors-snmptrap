# Use an official Python runtime as a base image
FROM python:3.6

ENV INSROOT /opt/app
ENV APPUSER snmptrap
ENV APPDIR ${INSROOT}/${APPUSER}

RUN useradd -d ${APPDIR} ${APPUSER}

WORKDIR ${APPDIR}

EXPOSE 162:162/udp

# Copy the current directory contents into the container at ${APPDIR}
COPY ./snmptrap/ ./bin/
COPY ./etc/ ./etc/
COPY requirements.txt ./
RUN pip install -r requirements.txt

RUN mkdir -p ${APPDIR}/data \
 && mkdir -p ${APPDIR}/logs \
 && mkdir -p ${APPDIR}/tmp \
 && chown -R ${APPUSER}:${APPUSER} ${APPDIR} \
 && chmod a+w ${APPDIR}/data \
 && chmod a+w ${APPDIR}/logs \
 && chmod a+w ${APPDIR}/tmp \
 && chmod 500 ${APPDIR}/etc \
 && chmod 500 ${APPDIR}/bin/snmptrapd.sh 

USER ${APPUSER}

VOLUME ${APPDIR}/logs

# Run run_policy.sh when the container launches
CMD ["./bin/snmptrapd.sh start"]
