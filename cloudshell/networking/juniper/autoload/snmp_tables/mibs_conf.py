from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject


class MIBS:
    JUNIPER_MIB = "JUNIPER-MIB"
    JUNIPER_IF_MIB = "JUNIPER-IF-MIB"
    IF_MIB = "IF-MIB"
    LAG_MIB = "IEEE8023-LAG-MIB"
    IP_MIB = "IP-MIB"
    IPV6_MIB = "IPV6-MIB"
    LLDP_MIB = "LLDP-MIB"
    SNMPV2_MIB = "SNMPv2-MIB"
    ETHERLIKE_MIB = "EtherLike-MIB"


class JUNOS_IFMIB_KEYS:
    PHIS_ID = "ifChassisPort"
    FPC = "ifChassisFpc"
    PIC = "ifChassisPic"
    LOGICAL_UNIT = "ifChassisLogicalUnit"


class JUNOS_MIB_KEYS:
    MODEL="jnxContentsModel"
    TYPE="jnxContentsType"
    DESCR="jnxContentsDescr"
    SERIAL_NO="jnxContentsSerialNo"
    REVISION="jnxContentsRevision"
    CHASSIS_ID="jnxContentsChassisId"
    BOX_DESCR="jnxBoxDescr"


class MIB_TABLES:
    JUNOS_STRUCT_TABLE = [
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.MODEL),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.TYPE),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.DESCR),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.SERIAL_NO),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.REVISION),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.CHASSIS_ID),
        SnmpMibObject(MIBS.JUNIPER_MIB, JUNOS_MIB_KEYS.BOX_DESCR),
    ]

    JUNOS_IF_TABLE = [
        SnmpMibObject(MIBS.JUNIPER_IF_MIB, JUNOS_IFMIB_KEYS.PHIS_ID),
        SnmpMibObject(MIBS.JUNIPER_IF_MIB, JUNOS_IFMIB_KEYS.FPC),
        SnmpMibObject(MIBS.JUNIPER_IF_MIB, JUNOS_IFMIB_KEYS.PIC),
        SnmpMibObject(MIBS.JUNIPER_IF_MIB, JUNOS_IFMIB_KEYS.LOGICAL_UNIT),
    ]
