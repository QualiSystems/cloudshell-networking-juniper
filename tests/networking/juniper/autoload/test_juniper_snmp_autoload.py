import os
from unittest import TestCase, skip

import sys

from cloudshell.networking.juniper.autoload.junos_snmp_autoload import JunosSnmpAutoload
import cloudshell.networking.juniper.autoload.junos_snmp_autoload as junos_snmp_autoload
from mock import MagicMock as Mock, patch, call, PropertyMock

from cloudshell.networking.juniper.autoload.mib_names import MIBS


class TestJunosSnmpAutoload(TestCase):
    FIREWALL_SHELL = 'CS_Firewall'
    SWITCH_SHELL = 'CS_Switch'
    ROUTER_SHELL = 'CS_Router'
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

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.JunosSnmpAutoload._initialize_snmp_handler')
    def _create_instance(self, initialize_snmp_handler):
        instance = JunosSnmpAutoload(self._snmp_service, self._logger)
        initialize_snmp_handler.assert_called_once_with()
        return instance

    # def _mock_methods(self, instance):
    #     instance._is_valid_device_os = Mock()
    #     instance.enable_snmp = Mock()
    #     instance.disable_snmp = Mock()
    #     instance._build_root = Mock()
    #     instance._build_chassis = Mock()
    #     instance._build_power_modules = Mock()
    #     instance._build_modules = Mock()
    #     instance._build_sub_modules = Mock()
    #     instance._build_ports = Mock()
    #     instance._root = Mock()
    #     instance._log_autoload_details = Mock()

    # def test_init_firewall(self):
    #     instance = self._create_instance(shell_type=self.FIREWALL_SHELL)
    #     self.assertIs(instance.shell_name, self._shell_name)
    #     self.assertIs(instance.shell_type, self.FIREWALL_SHELL)
    #     self.assertIs(instance.shell_type, self.FIREWALL_SHELL)
    #     self.assertIsNone(instance._content_indexes)
    #     self.assertIsNone(instance._if_indexes)
    #     self.assertIs(instance._logger, self._logger)
    #     self.assertIs(instance._snmp_handler, self._snmp_handler)
    #     self.assertIs(instance._resource_name, self._resource_name)
    #     self.assertIs(instance.resource, self._resource)
    #     self.assertEqual(instance._chassis, {})
    #     self.assertEqual(instance._modules, {})
    #     self.assertEqual(instance.sub_modules, {})
    #     self.assertEqual(instance._ports, {})
    #     self.assertEqual(instance._logical_generic_ports, {})
    #     self.assertEqual(instance._physical_generic_ports, {})
    #     self.assertIsNone(instance._generic_physical_ports_by_name)
    #     self.assertIsNone(instance._generic_logical_ports_by_name)
    #     self.assertIsNone(instance._ipv4_table)
    #     self.assertIsNone(instance._ipv6_table)
    #     self.assertIsNone(instance._if_duplex_table)
    #     self.assertIsNone(instance._autoneg)
    #     self.assertIsNone(instance._lldp_keys)

    # def test_init_switch(self):
    #     instance = self._create_instance(shell_type=self.SWITCH_SHELL)
    #     self.assertIs(instance.shell_name, self._shell_name)
    #     self.assertIs(instance.shell_type, self.SWITCH_SHELL)
    #     self.assertIsNone(instance._content_indexes)
    #     self.assertIsNone(instance._if_indexes)
    #     self.assertIs(instance._logger, self._logger)
    #     self.assertIs(instance._snmp_handler, self._snmp_handler)
    #     self.assertIs(instance._resource_name, self._resource_name)
    #     self.assertIs(instance.resource, self._resource)
    #     self.assertEqual(instance._chassis, {})
    #     self.assertEqual(instance._modules, {})
    #     self.assertEqual(instance.sub_modules, {})
    #     self.assertEqual(instance._ports, {})
    #     self.assertEqual(instance._logical_generic_ports, {})
    #     self.assertEqual(instance._physical_generic_ports, {})
    #     self.assertIsNone(instance._generic_physical_ports_by_name)
    #     self.assertIsNone(instance._generic_logical_ports_by_name)
    #     self.assertIsNone(instance._ipv4_table)
    #     self.assertIsNone(instance._ipv6_table)
    #     self.assertIsNone(instance._if_duplex_table)
    #     self.assertIsNone(instance._autoneg)
    #     self.assertIsNone(instance._lldp_keys)

    def test_logger_property(self):
        instance = self._create_instance()
        self.assertIs(instance._logger, self._logger)

    def test_snm_handler_property(self):
        instance = self._create_instance()
        self.assertIs(instance._snmp_service, self._snmp_service)

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.os')
    def test_initialize_snmp_handler(self, os):
        path_value = Mock()
        os.path.abspath.return_value = path_value
        os.path.join.return_value = path_value
        os.path.dirname.return_value = path_value
        instance = JunosSnmpAutoload(self._snmp_service, self._logger)
        os.path.dirname.assert_called_once_with(junos_snmp_autoload.__file__)
        os.path.join.assert_called_once_with(path_value, 'mibs')
        os.path.abspath.assert_called_once_with(path_value)
        self._snmp_service.add_mib_folder_path.assert_called_once_with(path_value)
        self._snmp_service.load_mib_tables.assert_called_once_with(
            [MIBS.JUNIPER_MIB, MIBS.JUNIPER_IF_MIB, MIBS.IF_MIB, MIBS.LAG_MIB, MIBS.IP_MIB, MIBS.IPV6_MIB,
             MIBS.LLDP_MIB, MIBS.ETHERLIKE_MIB])

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.SnmpMibObject')
    def test_device_info(self, snmp_mib_obj):
        val1 = "Test1"
        val2 = "Test2"
        self._snmp_service.get_property.side_effect = [Mock(safe_value=val1), Mock(safe_value=val2)]
        instance = self._create_instance()
        self.assertEqual(instance.device_info, val1 + val2)
        snmp_mib_obj.assert_has_calls(
            [call(MIBS.SNMPV2_MIB, 'sysDescr', '0'), call(MIBS.JUNIPER_MIB, 'jnxBoxDescr', '0')])
        self._snmp_service.get_property.assert_has_calls([call(snmp_mib_obj.return_value),
                                                          call(snmp_mib_obj.return_value)])

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.SnmpMibObject')
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
        container_indexes = [Mock(safe_value=index1, index=value1), Mock(safe_value=index2, index=value2),
                             Mock(safe_value=index3, index=value3), Mock(safe_value=index4, index=value4),
                             Mock(safe_value=index4, index=value5)]
        self._snmp_service.walk.return_value = container_indexes
        self.assertEqual(instance._content_indexes,
                         {1: [value1], index2: [value2], index3: [value3], index4: [value4, value5]})
        self._snmp_service.walk.assert_called_once_with(mib_obj_val)
        snmp_mib_obj.assert_called_once_with(MIBS.JUNIPER_MIB, 'jnxContentsContainerIndex')

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.SnmpMibObject')
    def test_if_indexes(self, snmp_mib_obj):
        index1 = '1'
        index2 = '2'
        self._snmp_service.walk.return_value = [Mock(index=index1), Mock(index=index2)]
        instance = self._create_instance()
        self.assertEquals(list(instance._if_indexes), [int(index1), int(index2)])
        snmp_mib_obj.assert_called_once_with(MIBS.JUNIPER_IF_MIB, 'ifChassisPort')
        self._snmp_service.walk.assert_called_once_with(snmp_mib_obj.return_value)

    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.SnmpMibObject')
    @patch('cloudshell.networking.juniper.autoload.junos_snmp_autoload.JunosSnmpAutoload.device_info',
           new_callable=PropertyMock)
    def test_build_root(self, device_info, snmp_mib_obj):
        vendor = 'Test_Vendor'
        model = 'Tets_Model'
        version = '12.1R6.5'
        contact_name = Mock()
        system_name = Mock()
        location = Mock()
        device_info.return_value = "TEst JUNOS {} #/test".format(version)
        self._snmp_service.get_property.side_effect = [
            Mock(safe_value="{0}-testjnxProductName{1}".format(vendor, model)),
            Mock(safe_value=contact_name),
            Mock(safe_value=system_name),
            Mock(safe_value=location)]
        instance = self._create_instance()
        instance.build_root(self._resource_model)
        self.assertIs(self._resource_model.contact_name, contact_name)
        self.assertIs(self._resource_model.system_name, system_name)
        self.assertIs(self._resource_model.location, location)
        self.assertEqual(self._resource_model.os_version, version)
        self.assertEqual(self._resource_model.vendor, vendor.capitalize())
        self.assertEqual(self._resource_model.model, model)
        calls = [call(MIBS.SNMPV2_MIB, 'sysObjectID', '0'),
                 call(MIBS.SNMPV2_MIB, 'sysContact', '0'), call(MIBS.SNMPV2_MIB, 'sysName', '0'),
                 call(MIBS.SNMPV2_MIB, 'sysLocation', '0')]
        snmp_mib_obj.assert_has_calls(calls)
        self._snmp_service.get_property.assert_has_calls(
            [call(snmp_mib_obj.return_value), call(snmp_mib_obj.return_value), call(snmp_mib_obj.return_value),
             call(snmp_mib_obj.return_value)])

    # def test_build_root2(self):
    #     instance = self._create_instance()
    #     vendor = 'Test_Vendor'
    #     model = 'Tets_Model'
    #     version = '12.1R6.5'
    #     contact_name = Mock()
    #     system_name = Mock()
    #     location = Mock()
    #     self._snmp_handler.get_property.side_effect = [
    #         "{0}-testjnxProduct{1}".format(vendor, model),
    #         "TEst JUNOS {} #/test".format(version),
    #         contact_name,
    #         system_name,
    #         location
    #     ]
    #
    #     instance._build_root()
    #
    #     self.assertIs(instance.resource.contact_name, contact_name)
    #     self.assertIs(instance.resource.system_name, system_name)
    #     self.assertIs(instance.resource.location, location)
    #     self.assertEqual(self._resource.os_version, version)
    #     self.assertEqual(self._resource.vendor, vendor.capitalize())
    #     self.assertEqual(self._resource.model, model)
    #     calls = [call('SNMPv2-MIB', 'sysObjectID', 0), call('SNMPv2-MIB', 'sysDescr', '0'),
    #              call('SNMPv2-MIB', 'sysContact', '0'), call('SNMPv2-MIB', 'sysName', '0'),
    #              call('SNMPv2-MIB', 'sysLocation', '0')]
    #     self._snmp_handler.get_property.assert_has_calls(calls)

    # @patch('cloudshell.networking.juniper.autoload.juniper_snmp_autoload.AutoloadDetailsBuilder')
    # def test_discover(self, autoload_details_builder_class):
    #     instance = self._create_instance()
    #     autoload_details_builder = Mock()
    #     autoload_details_builder_class.return_value = autoload_details_builder
    #     autoload_details = Mock()
    #     autoload_details_builder.autoload_details.return_value = autoload_details
    #     self._mock_methods(instance)
    #     self.assertIs(instance.discover(self._supported_os), autoload_details)
    #     instance._is_valid_device_os.assert_called_once_with(self._supported_os)
    #     instance._build_root.assert_called_once_with()
    #     instance._build_chassis.assert_called_once_with()
    #     instance._build_power_modules.assert_called_once_with()
    #     instance._build_modules.assert_called_once_with()
    #     instance._build_sub_modules.assert_called_once_with()
    #     instance._build_ports.assert_called_once_with()
    #     instance._log_autoload_details.assert_called_once_with(autoload_details)
    #     autoload_details_builder_class.assert_called_once_with(self._resource)
    #     autoload_details_builder.autoload_details.assert_called_once_with()
