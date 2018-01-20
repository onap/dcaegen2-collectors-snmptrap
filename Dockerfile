# Use an official Python runtime as a base image
FROM python:3.6

ENV INSROOT /opt/app
ENV APPUSER snmptrap
ENV APPDIR ${INSROOT}/${APPUSER}

RUN useradd -d ${APPDIR} ${APPUSER}

WORKDIR ${APPDIR}

EXPOSE 162

# Copy the current directory contents into the container at ${APPDIR}
COPY ./src/ ./bin/
COPY ./etc/ ./etc/

RUN mkdir -p ${APPDIR}/logs \
 && chown -R ${APPUSER}:${APPUSER} ${APPDIR} \
 && chmod a+w ${APPDIR}/logs \
 && chmod 500 ${APPDIR}/etc \
 && chmod 500 ${APPDIR}/bin/dcae_snmptrapd.sh 
 

USER ${APPUSER}

VOLUME ${APPDIR}/logs

# Run run_policy.sh when the container launches
CMD ["./bin/dcae_snmptrapd.sh"]
