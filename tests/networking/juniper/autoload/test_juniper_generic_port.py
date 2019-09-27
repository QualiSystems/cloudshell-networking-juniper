from unittest import TestCase

from cloudshell.networking.juniper.autoload.entities import JuniperGenericPort

try:
    from unittest.mock import Mock, PropertyMock, patch
except ImportError:
    from mock import Mock, PropertyMock, patch


class TestJuniperGenericPort(TestCase):
    def setUp(self):
        self._index = Mock()
        self._snmp_service = Mock()
        self._resource_model = Mock()
        self._get_snmp_attribute_mock = None

    @patch("cloudshell.networking.juniper.autoload.entities.SnmpMibObject")
    def test_get_snmp_attribute(self, snmp_mib_object):
        instance = JuniperGenericPort(
            self._index, self._snmp_service, self._resource_model
        )
        value = Mock()
        self._snmp_service.get_property.return_value = Mock(safe_value=value)
        mib = Mock()
        snmp_attribute = Mock()
        self.assertEquals(instance._get_snmp_attribute(mib, snmp_attribute), value)
        snmp_mib_object.assert_called_once_with(mib, snmp_attribute, self._index)
        self._snmp_service.get_property.assert_called_once_with(
            snmp_mib_object.return_value
        )

    @patch(
        "cloudshell.networking.juniper.autoload.entities."
        "JuniperGenericPort.port_name",
        new_callable=PropertyMock,
    )
    @patch(
        "cloudshell.networking.juniper.autoload.entities."
        "JuniperGenericPort._get_snmp_attribute"
    )
    def _create_port_instance(self, get_snmp_attribute, port_name):
        port_name.return_value = "port"
        self._get_snmp_attribute_mock = get_snmp_attribute
        return JuniperGenericPort(self._index, self._snmp_service, self._resource_model)

    @patch(
        "cloudshell.networking.juniper.autoload.juniper_snmp_autoload."
        "JuniperGenericPort.port_name",
        new_callable=PropertyMock,
    )
    @patch(
        "cloudshell.networking.juniper.autoload.entities."
        "JuniperGenericPort._get_snmp_attribute"
    )
    def _create_portchannel_instance(self, get_snmp_attribute, port_name):
        self._get_snmp_attribute_mock = get_snmp_attribute
        port_name.return_value = "ae1"
        return JuniperGenericPort(self._index, self._snmp_service, self._resource_model)
