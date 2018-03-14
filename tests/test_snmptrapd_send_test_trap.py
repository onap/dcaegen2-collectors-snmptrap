from pysnmp.hlapi import *
from pysnmp import debug

# debug.setLogger(debug.Debug('msgproc'))

iters = range(0, 10, 1)
for i in iters:
    errorIndication, errorStatus, errorIndex, varbinds = next(sendNotification(SnmpEngine(),
         CommunityData('not_public'),
         UdpTransportTarget(('localhost', 6164)),
         ContextData(),
         'trap',
         [ObjectType(ObjectIdentity('.1.3.6.1.4.1.999.1'), OctetString('test trap - ignore')),
          ObjectType(ObjectIdentity('.1.3.6.1.4.1.999.2'), OctetString('ONAP pytest trap'))])
    )
    
    if errorIndication:
        print(errorIndication)
    else:
        print("successfully sent first trap example, number %d" % i)

for i in iters:
    errorIndication, errorStatus, errorIndex, varbinds = next(sendNotification(SnmpEngine(),
         CommunityData('public'),
         UdpTransportTarget(('localhost', 6164)),
         ContextData(),
         'trap',
            NotificationType(
                ObjectIdentity('.1.3.6.1.4.1.74.2.46.12.1.1')
            ).addVarBinds(
                ('.1.3.6.1.4.1.999.1', OctetString('ONAP pytest trap - ignore (varbind 1)')),
                ('.1.3.6.1.4.1.999.2', OctetString('ONAP pytest trap - ignore (varbind 2)'))
            )
        )
    )

    if errorIndication:
        print(errorIndication)
    else:
        print("successfully sent second trap example, number %d" % i)
