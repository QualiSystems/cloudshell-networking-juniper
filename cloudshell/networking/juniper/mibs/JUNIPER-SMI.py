# PySNMP SMI module. Autogenerated from smidump -f python JUNIPER-SMI
# by libsmi2pysnmp-0.1.3 at Wed Jan 20 11:51:54 2016,
# Python version sys.version_info(major=2, minor=7, micro=6, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( Bits, Integer32, ModuleIdentity, MibIdentifier, ObjectIdentity, TimeTicks, enterprises, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Integer32", "ModuleIdentity", "MibIdentifier", "ObjectIdentity", "TimeTicks", "enterprises")

# Objects

juniperMIB = ModuleIdentity((1, 3, 6, 1, 4, 1, 2636)).setRevisions(("2012-02-10 00:00","2011-01-26 00:00","2010-07-14 00:00","2010-07-09 00:00","2010-07-09 00:00","2010-06-18 00:00","2009-12-31 00:00","2009-10-29 00:00","2007-10-09 00:00","2007-01-01 00:00","2006-12-14 01:00","2005-08-17 01:00","2003-04-17 01:00",))
if mibBuilder.loadTexts: juniperMIB.setOrganization("Juniper Networks, Inc.")
if mibBuilder.loadTexts: juniperMIB.setContactInfo("        Juniper Technical Assistance Center\nJuniper Networks, Inc.\n1194 N. Mathilda Avenue\nSunnyvale, CA 94089\nE-mail: support@juniper.net")
if mibBuilder.loadTexts: juniperMIB.setDescription("The Structure of Management Information for Juniper Networks.")
jnxProducts = ObjectIdentity((1, 3, 6, 1, 4, 1, 2636, 1))
if mibBuilder.loadTexts: jnxProducts.setDescription("The root of Juniper's Product OIDs.")
jnxMediaFlow = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 1, 2))
jnxReservedProducts3 = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 1, 4))
jnxReservedProducts4 = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 1, 5))
jnxReservedProducts5 = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 1, 6))
jnxServices = ObjectIdentity((1, 3, 6, 1, 4, 1, 2636, 2))
if mibBuilder.loadTexts: jnxServices.setDescription("The root of Juniper's Services OIDs.")
jnxMibs = ObjectIdentity((1, 3, 6, 1, 4, 1, 2636, 3))
if mibBuilder.loadTexts: jnxMibs.setDescription("The root of Juniper's MIB objects.")
jnxJsMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 39))
jnxExMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 40))
jnxWxMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 41))
jnxDcfMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 42))
jnxReservedMibs5 = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 43))
jnxPfeMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 44))
jnxBfdMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 45))
jnxXstpMibs = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 46))
jnxUtilMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 47))
jnxl2aldMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 48))
jnxL2tpMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 49))
jnxRpmMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 50))
jnxUserAAAMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 51))
jnxIpSecMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 52))
jnxL2cpMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 53))
jnxPwTdmMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 54))
jnxPwTCMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 55))
jnxOtnMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 56))
jnxPsuMIBRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 58))
jnxSvcsMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 59))
jnxDomMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 60))
jnxJdhcpMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 61))
jnxJdhcpv6MibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 62))
jnxLicenseMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 63))
jnxSubscriberMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 64))
jnxMagMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 65))
jnxPppoeMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 67))
jnxPppMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 3, 68))
jnxTraps = ObjectIdentity((1, 3, 6, 1, 4, 1, 2636, 4))
if mibBuilder.loadTexts: jnxTraps.setDescription("The root of Juniper's Trap OIDs.")
jnxChassisTraps = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 1))
jnxChassisOKTraps = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 2))
jnxRmonTraps = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 3))
jnxLdpTraps = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 4))
jnxCmNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 5))
jnxSonetNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 6))
jnxPMonNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 7))
jnxCollectorNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 8))
jnxPingNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 9))
jnxSpNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 10))
jnxDfcNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 11))
jnxSyslogNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 12))
jnxEventNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 13))
jnxVccpNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 14))
jnxOtnNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 15))
jnxSAIDPNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 16))
jnxCosNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 17))
jnxDomNotifications = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 4, 18))
jnxExperiment = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 5))
jnxNsm = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 6))
jnxCA = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 7))
jnxAAA = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 8))
jnxAdvancedInsightMgr = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 9))
jnxBxMibRoot = MibIdentifier((1, 3, 6, 1, 4, 1, 2636, 10))

# Augmentions

# Exports

# Module identity
mibBuilder.exportSymbols("JUNIPER-SMI", PYSNMP_MODULE_ID=juniperMIB)

# Objects
mibBuilder.exportSymbols("JUNIPER-SMI", juniperMIB=juniperMIB, jnxProducts=jnxProducts, jnxMediaFlow=jnxMediaFlow, jnxReservedProducts3=jnxReservedProducts3, jnxReservedProducts4=jnxReservedProducts4, jnxReservedProducts5=jnxReservedProducts5, jnxServices=jnxServices, jnxMibs=jnxMibs, jnxJsMibRoot=jnxJsMibRoot, jnxExMibRoot=jnxExMibRoot, jnxWxMibRoot=jnxWxMibRoot, jnxDcfMibRoot=jnxDcfMibRoot, jnxReservedMibs5=jnxReservedMibs5, jnxPfeMibRoot=jnxPfeMibRoot, jnxBfdMibRoot=jnxBfdMibRoot, jnxXstpMibs=jnxXstpMibs, jnxUtilMibRoot=jnxUtilMibRoot, jnxl2aldMibRoot=jnxl2aldMibRoot, jnxL2tpMibRoot=jnxL2tpMibRoot, jnxRpmMibRoot=jnxRpmMibRoot, jnxUserAAAMibRoot=jnxUserAAAMibRoot, jnxIpSecMibRoot=jnxIpSecMibRoot, jnxL2cpMibRoot=jnxL2cpMibRoot, jnxPwTdmMibRoot=jnxPwTdmMibRoot, jnxPwTCMibRoot=jnxPwTCMibRoot, jnxOtnMibRoot=jnxOtnMibRoot, jnxPsuMIBRoot=jnxPsuMIBRoot, jnxSvcsMibRoot=jnxSvcsMibRoot, jnxDomMibRoot=jnxDomMibRoot, jnxJdhcpMibRoot=jnxJdhcpMibRoot, jnxJdhcpv6MibRoot=jnxJdhcpv6MibRoot, jnxLicenseMibRoot=jnxLicenseMibRoot, jnxSubscriberMibRoot=jnxSubscriberMibRoot, jnxMagMibRoot=jnxMagMibRoot, jnxPppoeMibRoot=jnxPppoeMibRoot, jnxPppMibRoot=jnxPppMibRoot, jnxTraps=jnxTraps, jnxChassisTraps=jnxChassisTraps, jnxChassisOKTraps=jnxChassisOKTraps, jnxRmonTraps=jnxRmonTraps, jnxLdpTraps=jnxLdpTraps, jnxCmNotifications=jnxCmNotifications, jnxSonetNotifications=jnxSonetNotifications, jnxPMonNotifications=jnxPMonNotifications, jnxCollectorNotifications=jnxCollectorNotifications, jnxPingNotifications=jnxPingNotifications, jnxSpNotifications=jnxSpNotifications, jnxDfcNotifications=jnxDfcNotifications, jnxSyslogNotifications=jnxSyslogNotifications, jnxEventNotifications=jnxEventNotifications, jnxVccpNotifications=jnxVccpNotifications, jnxOtnNotifications=jnxOtnNotifications, jnxSAIDPNotifications=jnxSAIDPNotifications, jnxCosNotifications=jnxCosNotifications, jnxDomNotifications=jnxDomNotifications, jnxExperiment=jnxExperiment, jnxNsm=jnxNsm, jnxCA=jnxCA, jnxAAA=jnxAAA, jnxAdvancedInsightMgr=jnxAdvancedInsightMgr, jnxBxMibRoot=jnxBxMibRoot)

