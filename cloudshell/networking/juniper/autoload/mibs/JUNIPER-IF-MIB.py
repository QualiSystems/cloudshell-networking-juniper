# PySNMP SMI module. Autogenerated from smidump -f python JUNIPER-IF-MIB
# by libsmi2pysnmp-0.1.3 at Thu Jan 21 14:52:14 2016,
# Python version sys.version_info(major=2, minor=7, micro=6, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( CounterBasedGauge64, ) = mibBuilder.importSymbols("HCNUM-TC", "CounterBasedGauge64")
( ifEntry, ifIndex, ) = mibBuilder.importSymbols("IF-MIB", "ifEntry", "ifIndex")
( jnxMibs, ) = mibBuilder.importSymbols("JUNIPER-SMI", "jnxMibs")
( Bits, Counter32, Counter64, Gauge32, Integer32, Integer32, ModuleIdentity, MibIdentifier, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Counter32", "Counter64", "Gauge32", "Integer32", "Integer32", "ModuleIdentity", "MibIdentifier", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks")
( TimeStamp, ) = mibBuilder.importSymbols("SNMPv2-TC", "TimeStamp")

# Objects

ifJnx = ModuleIdentity((1, 3, 6, 1, 4, 1, 2636, 3, 3)).setRevisions(("2007-06-05 00:00","2003-07-18 21:53","2002-10-31 00:00","2001-06-21 00:00","2001-03-15 00:00",))
if mibBuilder.loadTexts: ifJnx.setOrganization("Juniper Networks, Inc.")
if mibBuilder.loadTexts: ifJnx.setContactInfo("        Juniper Technical Assistance Center\nJuniper Networks, Inc.\n1194 N. Mathilda Avenue\nSunnyvale, CA 94089\nE-mail: support@juniper.net")
if mibBuilder.loadTexts: ifJnx.setDescription("The MIB modules extends the ifTable as\ndefined in IF-MIB.")
ifJnxTable = MibTable((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1))
if mibBuilder.loadTexts: ifJnxTable.setDescription("A list of Juniper's extension to the interface entries.\nThe number of entries is given by the value of ifNumber.\nThis table contains additional objects for the interface\ntable.")
ifJnxEntry = MibTableRow((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1))
if mibBuilder.loadTexts: ifJnxEntry.setDescription("An entry containing additional management information\napplicable to a particular interface.")
ifIn1SecRate = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 1), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifIn1SecRate.setDescription("The number of bits per second (bps), delivered by \nthis (sub-)layer to its next higher (sub-)layer.")
ifIn1SecOctets = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 2), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifIn1SecOctets.setDescription("The number of octets per second (Bps, Bytes per \nsecond), delivered by this (sub-)layer to its next\nhigher (sub-)layer.")
ifIn1SecPkts = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 3), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifIn1SecPkts.setDescription("The number of packets per second (pps), delivered\nby this (sub-)layer to its next higher (sub-)layer.")
ifOut1SecRate = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 4), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifOut1SecRate.setDescription("The number of bits per second (bps), delivered by\nthis (sub-)layer to its next lower (sub-)layer.")
ifOut1SecOctets = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 5), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifOut1SecOctets.setDescription("The number of octets per second (Bps, Bytes per\nsecond), delivered by this (sub-)layer to its next\nlower (sub-)layer.")
ifOut1SecPkts = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 6), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifOut1SecPkts.setDescription("The number of packets per second (pps), delivered\nby this (sub-)layer to its next lower (sub-)layer.")
ifHCIn1SecRate = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 7), CounterBasedGauge64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifHCIn1SecRate.setDescription("The number of bits per second (bps), delivered by \nthis (sub-)layer to its next higher (sub-)layer.\nThis object is a 64 bit version of ifIn1SecRate.")
ifHCOut1SecRate = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 8), CounterBasedGauge64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifHCOut1SecRate.setDescription("The number of bits per second (bps), delivered by\nthis (sub-)layer to its next lower (sub-)layer.\nThis object is a 64 bit version of ifOut1SecRate.")
ifJnxInErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 9), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInErrors.setDescription("Errors: The sum of the incoming frame aborts and FCS errors.")
ifJnxInFrameErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 10), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInFrameErrors.setDescription("Framing Errors: The number of input packets which were \nmisaligned.")
ifJnxInQDrops = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 11), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInQDrops.setDescription("Drops: The number of packets dropped by the input queue of \nthe I/O Manager ASIC.")
ifJnxInRunts = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 12), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInRunts.setDescription("Runts: Frames received that are smaller than the runt \nthreshold.")
ifJnxInGiants = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 13), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInGiants.setDescription("Giants: Frames received that are larger than the giant \nthreshold.")
ifJnxInDiscards = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 14), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInDiscards.setDescription("Policed Discards: Frames that the incoming packet match code \ndiscarded because they were not recognized or of interest.")
ifJnxInHslCrcErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 15), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInHslCrcErrors.setDescription("HS Link CRC Errors: The number of CRC errors on the \nhigh-speed links between the ASICs responsible for handling \nthe router interfaces while receiving packets.")
ifJnxInHslFifoOverFlows = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 16), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInHslFifoOverFlows.setDescription("HS link FIFO overflows: The number of FIFO overflows on the\nhigh-speed links between the ASICs responsible for handling\nthe router interfaces.")
ifJnxInL3Incompletes = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 17), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInL3Incompletes.setDescription("L3 incompletes: The number of incoming packets that fail\nLayer 3 sanity checks of the header.")
ifJnxInL2ChanErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 18), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInL2ChanErrors.setDescription("L2 channel errors: the number of incoming packets for which \nthe sofware could not find a valid logical interface.")
ifJnxInL2MismatchTimeouts = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 19), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInL2MismatchTimeouts.setDescription("L2 mismatch timeouts: The count of malformed or short packets\nthat cause the incoming packet handler to discard the frame\nas unreadable.")
ifJnxInInvalidVCs = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 20), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInInvalidVCs.setDescription("Invalid VCs: Number of cells that arrived for a nonexistent\nvirtual circuit.")
ifJnxInFifoErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 21), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxInFifoErrors.setDescription("FIFO errors: The number of FIFO errors in the receive\ndirection as reported by the ASIC on the PIC.")
ifJnxBucketDrops = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 22), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxBucketDrops.setDescription("Bucket drops: Drops due to traffic load exceeding the\ninterface transmit/receive leaky bucket configuration.")
ifJnxSramErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 23), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxSramErrors.setDescription("SRAM errors: This counter increments when a hardware error\nhas occurred in the SRAM on the PIC.")
ifJnxOutErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 24), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutErrors.setDescription("Errors: The sum of the outgoing frame aborts and FCS errors.")
ifJnxCollisions = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 25), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxCollisions.setDescription("Collisions: The number of output collisions detected on this\ninterface.")
ifJnxCarrierTrans = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 26), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxCarrierTrans.setDescription("Carrier transitions: The number of times the interface saw\nthe carrier signal transition.")
ifJnxOutQDrops = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 27), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutQDrops.setDescription("Drops: The number of packets dropped by the output queue of\nthe I/O Manager ASIC.")
ifJnxOutAgedErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 28), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutAgedErrors.setDescription("Aged packets: The number of packets that remained in shared\npacket SDRAM for so long that the system automatically purged\nthem.")
ifJnxOutFifoErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 29), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutFifoErrors.setDescription("FIFO errors: The number of FIFO errors in the transmit\ndirection as reported by the ASIC on the PIC.")
ifJnxOutHslFifoUnderFlows = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 30), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutHslFifoUnderFlows.setDescription("HS link FIFO underflows: The number of FIFO underflows on the\nhigh-speed links between the ASICs responsible for handling\nthe router interfaces.")
ifJnxOutHslCrcErrors = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 1, 1, 31), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifJnxOutHslCrcErrors.setDescription("HS Link CRC Errors: The number of CRC errors on the \nhigh-speed links between the ASICs responsible for handling \nthe router interfaces while transmitting packets.")
ifChassisTable = MibTable((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2))
if mibBuilder.loadTexts: ifChassisTable.setDescription("A list of Juniper's extension to the interface entries.\nThe number of entries is given by the value of ifNumber.\nThis table contains additional objects for the interface\ntable to facilitate the identification of interfaces and\nits mapping into the Chassis MIB tables.")
ifChassisEntry = MibTableRow((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1))
if mibBuilder.loadTexts: ifChassisEntry.setDescription("An entry containing additional management information\napplicable to a particular interface.")
ifChassisFpc = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 1), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisFpc.setDescription("The number of the FPC card on which the interface\nis located in the chassis.  It is the chassis slot \nin which the FPC card is installed for the specified \ninterface.  \n\nAlthough the number is labeled from 0 and up in the \nchassis, the return value for this object always starts\nfrom 1 according to Network Management convention.\nTherefore, a value of zero means there is no real or\nphysical FPC associated with the specified interface.")
ifChassisPic = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 2), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisPic.setDescription("The number of the PIC card on which the interface\nis located in the chassis.  It is the PIC location \non the FPC card for the specified interface.\n\nAlthough the number is labeled from 0 and up in the \nchassis, the return value for this object always starts\nfrom 1 according to Network Management convention.\nTherefore, a value of zero means there is no real or\nphysical PIC associated with the specified interface.")
ifChassisPort = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 3), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisPort.setDescription("The number of the port on the PIC card on which the \ninterface is located in the chassis.  It is the port \nnumber on the PIC card for the specified interface.\n\nAlthough the number is labeled from 0 and up in the \nchassis, the return value for this object always starts\nfrom 1 according to Network Management convention.\nTherefore, a value of zero means there is no real or\nphysical port associated with the specified interface.")
ifChassisChannel = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 4), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisChannel.setDescription("The channel identifier for the specified interface\nif and only if it is part of a channelized interface.\n\nAlthough the channel is numbered from 0 and up in the \ninterface naming, the return value for this object \nalways starts from 1 according to Network Management \nconvention.  For the interface which could not be \nchannelized, this object returns zero.")
ifChassisLogicalUnit = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 5), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisLogicalUnit.setDescription("The logical unit number of the specified interface.\nIt is the logical part of the interface that is \nconfigured on the physical or channel part if any.\n\nAlthough the logical unit number is numbered from 0 and\nup in the interface naming, the return value for this \nobject always starts from 1 according to Network \nManagement convention.  For the interface which is \nreally a physical device, this value returns zero.")
ifChassisPicIndex = MibTableColumn((1, 3, 6, 1, 4, 1, 2636, 3, 3, 2, 1, 6), OctetString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ifChassisPicIndex.setDescription("The index or indices for the Chassis MIB tables.\nThis is the instance index which keys into the \njnxContentsTable in Chassis MIB.\n\nFor example, it could return an octet string of\n'8.1.2.0' - meaning a PIC ('8', first digit) \nat FPC slot 0 ('1-1', second digit minus one if nonzero)\nPIC number 1 ('2-1', third digit minus one if nonzero)\nport number whatever (fourth digit currently unused)\n- which in turn could be plugged in by NMS directly\nafter any MIB objects in the jnxContentsTable, say\n'jnxContentsDescr.8.1.2.0', so NMS could get that\nPIC object for the specified interface.\n\nThis object is valid only for those interfaces having \nreal and physical PIC cards.  Otherwise, it returns \nan octet string	of four zeros '0.0.0.0.'")

# Augmentions
ifEntry, = mibBuilder.importSymbols("IF-MIB", "ifEntry")
ifEntry.registerAugmentions(("JUNIPER-IF-MIB", "ifJnxEntry"))
ifJnxEntry.setIndexNames(*ifEntry.getIndexNames())
ifEntry, = mibBuilder.importSymbols("IF-MIB", "ifEntry")
ifEntry.registerAugmentions(("JUNIPER-IF-MIB", "ifChassisEntry"))
ifChassisEntry.setIndexNames(*ifEntry.getIndexNames())

# Exports

# Module identity
mibBuilder.exportSymbols("JUNIPER-IF-MIB", PYSNMP_MODULE_ID=ifJnx)

# Objects
mibBuilder.exportSymbols("JUNIPER-IF-MIB", ifJnx=ifJnx, ifJnxTable=ifJnxTable, ifJnxEntry=ifJnxEntry, ifIn1SecRate=ifIn1SecRate, ifIn1SecOctets=ifIn1SecOctets, ifIn1SecPkts=ifIn1SecPkts, ifOut1SecRate=ifOut1SecRate, ifOut1SecOctets=ifOut1SecOctets, ifOut1SecPkts=ifOut1SecPkts, ifHCIn1SecRate=ifHCIn1SecRate, ifHCOut1SecRate=ifHCOut1SecRate, ifJnxInErrors=ifJnxInErrors, ifJnxInFrameErrors=ifJnxInFrameErrors, ifJnxInQDrops=ifJnxInQDrops, ifJnxInRunts=ifJnxInRunts, ifJnxInGiants=ifJnxInGiants, ifJnxInDiscards=ifJnxInDiscards, ifJnxInHslCrcErrors=ifJnxInHslCrcErrors, ifJnxInHslFifoOverFlows=ifJnxInHslFifoOverFlows, ifJnxInL3Incompletes=ifJnxInL3Incompletes, ifJnxInL2ChanErrors=ifJnxInL2ChanErrors, ifJnxInL2MismatchTimeouts=ifJnxInL2MismatchTimeouts, ifJnxInInvalidVCs=ifJnxInInvalidVCs, ifJnxInFifoErrors=ifJnxInFifoErrors, ifJnxBucketDrops=ifJnxBucketDrops, ifJnxSramErrors=ifJnxSramErrors, ifJnxOutErrors=ifJnxOutErrors, ifJnxCollisions=ifJnxCollisions, ifJnxCarrierTrans=ifJnxCarrierTrans, ifJnxOutQDrops=ifJnxOutQDrops, ifJnxOutAgedErrors=ifJnxOutAgedErrors, ifJnxOutFifoErrors=ifJnxOutFifoErrors, ifJnxOutHslFifoUnderFlows=ifJnxOutHslFifoUnderFlows, ifJnxOutHslCrcErrors=ifJnxOutHslCrcErrors, ifChassisTable=ifChassisTable, ifChassisEntry=ifChassisEntry, ifChassisFpc=ifChassisFpc, ifChassisPic=ifChassisPic, ifChassisPort=ifChassisPort, ifChassisChannel=ifChassisChannel, ifChassisLogicalUnit=ifChassisLogicalUnit, ifChassisPicIndex=ifChassisPicIndex)
