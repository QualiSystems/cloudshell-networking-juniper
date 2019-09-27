from unittest import TestCase

import cloudshell.networking.juniper.autoload.junos_snmp_autoload as junos_snmp_autoload
from cloudshell.networking.juniper.autoload.junos_snmp_autoload import JunosSnmpAutoload
from cloudshell.networking.juniper.autoload.mib_names import MIBS

try:
    from unittest.mock import Mock, PropertyMock, patch, call
except ImportError:
    from mock import Mock, PropertyMock, patch, call


class TestJunosSnmpAutoload(TestCase):
    FIREWALL_SHELL = "CS_Firewall"
    SWITCH_SHELL = "CS_Switch"
    ROUTER_SHELL = "CS_Router"
    NETWORKING_MODEL_TYPES = [SWITCH_SHELL, ROUTER_SHELL]
    FIREWALL_MODEL_TYPES = [FIREWALL_SHELL]

    def setUp(self):
        self._snmp_service = Mock()
        self._shell_name = Mock()
        self._resource_name = Mock()
        self._logger = Mock()
        self._supported_os = Mock()
        self._resource = Mock()
        self._resource_model = Mock()

    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload."
        "JunosSnmpAutoload._initialize_snmp_handler"
    )
    def _create_instance(self, initialize_snmp_handler):
        instance = JunosSnmpAutoload(self._snmp_service, self._logger)
        initialize_snmp_handler.assert_called_once_with()
        return instance

    def test_logger_property(self):
        instance = self._create_instance()
        self.assertIs(instance._logger, self._logger)

    def test_snm_handler_property(self):
        instance = self._create_instance()
        self.assertIs(instance._snmp_service, self._snmp_service)

    @patch("cloudshell.networking.juniper.autoload.junos_snmp_autoload.os")
    def test_initialize_snmp_handler(self, os):
        path_value = Mock()
        os.path.abspath.return_value = path_value
        os.path.join.return_value = path_value
        os.path.dirname.return_value = path_value
        JunosSnmpAutoload(self._snmp_service, self._logger)
        os.path.dirname.assert_called_once_with(junos_snmp_autoload.__file__)
        os.path.join.assert_called_once_with(path_value, "mibs")
        os.path.abspath.assert_called_once_with(path_value)
        self._snmp_service.add_mib_folder_path.assert_called_once_with(path_value)
        self._snmp_service.load_mib_tables.assert_called_once_with(
            [
                MIBS.JUNIPER_MIB,
                MIBS.JUNIPER_IF_MIB,
                MIBS.IF_MIB,
                MIBS.LAG_MIB,
                MIBS.IP_MIB,
                MIBS.IPV6_MIB,
                MIBS.LLDP_MIB,
                MIBS.ETHERLIKE_MIB,
            ]
        )

    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload." "SnmpMibObject"
    )
    def test_device_info(self, snmp_mib_obj):
        val1 = "Test1"
        val2 = "Test2"
        self._snmp_service.get_property.side_effect = [
            Mock(safe_value=val1),
            Mock(safe_value=val2),
        ]
        instance = self._create_instance()
        self.assertEqual(instance.device_info, val1 + val2)
        snmp_mib_obj.assert_has_calls(
            [
                call(MIBS.SNMPV2_MIB, "sysDescr", "0"),
                call(MIBS.JUNIPER_MIB, "jnxBoxDescr", "0"),
            ]
        )
        self._snmp_service.get_property.assert_has_calls(
            [call(snmp_mib_obj.return_value), call(snmp_mib_obj.return_value)]
        )

    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload." "SnmpMibObject"
    )
    def test_get_content_indexes(self, snmp_mib_obj):
        mib_obj_val = Mock()
        snmp_mib_obj.return_value = mib_obj_val
        instance = self._create_instance()
        index1 = 1
        index2 = 2
        index3 = 7
        index4 = 8
        value1 = Mock()
        value2 = Mock()
        value3 = Mock()
        value4 = Mock()
        value5 = Mock()
        container_indexes = [
            Mock(safe_value=index1, index=value1),
            Mock(safe_value=index2, index=value2),
            Mock(safe_value=index3, index=value3),
            Mock(safe_value=index4, index=value4),
            Mock(safe_value=index4, index=value5),
        ]
        self._snmp_service.walk.return_value = container_indexes
        self.assertEqual(
            instance._content_indexes,
            {1: [value1], index2: [value2], index3: [value3], index4: [value4, value5]},
        )
        self._snmp_service.walk.assert_called_once_with(mib_obj_val)
        snmp_mib_obj.assert_called_once_with(
            MIBS.JUNIPER_MIB, "jnxContentsContainerIndex"
        )

    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload." "SnmpMibObject"
    )
    def test_if_indexes(self, snmp_mib_obj):
        index1 = "1"
        index2 = "2"
        self._snmp_service.walk.return_value = [Mock(index=index1), Mock(index=index2)]
        instance = self._create_instance()
        self.assertEquals(list(instance._if_indexes), [int(index1), int(index2)])
        snmp_mib_obj.assert_called_once_with(MIBS.JUNIPER_IF_MIB, "ifChassisPort")
        self._snmp_service.walk.assert_called_once_with(snmp_mib_obj.return_value)

    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload." "SnmpMibObject"
    )
    @patch(
        "cloudshell.networking.juniper.autoload.junos_snmp_autoload."
        "JunosSnmpAutoload.device_info",
        new_callable=PropertyMock,
    )
    def test_build_root(self, device_info, snmp_mib_obj):
        vendor = "Test_Vendor"
        model = "Tets_Model"
        version = "12.1R6.5"
        contact_name = Mock()
        system_name = Mock()
        location = Mock()
        device_info.return_value = "TEst JUNOS {} #/test".format(version)
        self._snmp_service.get_property.side_effect = [
            Mock(safe_value="{0}-testjnxProductName{1}".format(vendor, model)),
            Mock(safe_value=contact_name),
            Mock(safe_value=system_name),
            Mock(safe_value=location),
        ]
        instance = self._create_instance()
        instance.build_root(self._resource_model)
        self.assertIs(self._resource_model.contact_name, contact_name)
        self.assertIs(self._resource_model.system_name, system_name)
        self.assertIs(self._resource_model.location, location)
        self.assertEqual(self._resource_model.os_version, version)
        self.assertEqual(self._resource_model.vendor, vendor.capitalize())
        self.assertEqual(self._resource_model.model, model)
        calls = [
            call(MIBS.SNMPV2_MIB, "sysObjectID", "0"),
            call(MIBS.SNMPV2_MIB, "sysContact", "0"),
            call(MIBS.SNMPV2_MIB, "sysName", "0"),
            call(MIBS.SNMPV2_MIB, "sysLocation", "0"),
        ]
        snmp_mib_obj.assert_has_calls(calls)
        self._snmp_service.get_property.assert_has_calls(
            [
                call(snmp_mib_obj.return_value),
                call(snmp_mib_obj.return_value),
                call(snmp_mib_obj.return_value),
                call(snmp_mib_obj.return_value),
            ]
        )
