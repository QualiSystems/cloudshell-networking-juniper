import re

from cloudshell.networking.juniper.helpers.add_remove_vlan_helper import AddRemoveVlanHelper


class JuniperGenericPort(object):
    """
    Collect information and build Port or PortChannel
    """
    PORTCHANNEL_NAME_PATTERN = re.compile(r'ae\d+', re.IGNORECASE)
    AUTOLOAD_MAX_STRING_LENGTH = 100

    JUNIPER_IF_MIB = 'JUNIPER-IF-MIB'
    IF_MIB = 'IF-MIB'
    ETHERLIKE_MIB = 'EtherLike-MIB'

    def __init__(self, index, snmp_service, resource_model):
        """
        Create GenericPort with index and snmp handler
        :param int index:
        :param cloudshell.snmp.core.snmp_service.SnmpService snmp_service:
        :param  resource_model:
        :type resource_model: cloudshell.shell.standards.networking.autoload_model.NetworkingResourceModel|cloudshell.shell.standards.firewall.autoload_model.FirewallResourceModel
        """
        self.index = index
        self._snmp_service = snmp_service
        self._resource_model = resource_model

        self.associated_port_names = []
        self._port_phis_id = None
        self._port_name = None
        self._logical_unit = None
        self._fpc_id = None
        self._pic_id = None
        self._type = None

        self.ipv4_addresses = []
        self.ipv6_addresses = []
        self.port_adjacent = None

        self._max_string_length = self.AUTOLOAD_MAX_STRING_LENGTH

    def _get_snmp_attribute(self, mib, snmp_attribute):
        return self._snmp_service.get_property(mib, snmp_attribute, self.index)

    @property
    def port_phis_id(self):
        if not self._port_phis_id:
            self._port_phis_id = self._get_snmp_attribute(self.JUNIPER_IF_MIB, 'ifChassisPort')
        return self._port_phis_id

    @property
    def port_description(self):
        return self._get_snmp_attribute('IF-MIB', 'ifAlias')

    @property
    def logical_unit(self):
        if not self._logical_unit:
            self._logical_unit = self._get_snmp_attribute(self.JUNIPER_IF_MIB, 'ifChassisLogicalUnit')
        return self._logical_unit

    @property
    def fpc_id(self):
        if not self._fpc_id:
            self._fpc_id = self._get_snmp_attribute(self.JUNIPER_IF_MIB, 'ifChassisFpc')
        return self._fpc_id

    @property
    def pic_id(self):
        if not self._pic_id:
            self._pic_id = self._get_snmp_attribute(self.JUNIPER_IF_MIB, 'ifChassisPic')
        return self._pic_id

    @property
    def type(self):
        if not self._type:
            self._type = self._get_snmp_attribute(self.IF_MIB, 'ifType').strip('\'')
        return self._type

    @property
    def port_name(self):
        if not self._port_name:
            self._port_name = self._get_snmp_attribute(self.IF_MIB, 'ifDescr')
        return self._port_name

    @property
    def is_portchannel(self):
        return True if re.match(self.PORTCHANNEL_NAME_PATTERN, self.port_name) else False

    def _get_associated_ipv4_address(self):
        return self._validate_attribute_value(','.join(self.ipv4_addresses))

    def _get_associated_ipv6_address(self):
        return self._validate_attribute_value(','.join(self.ipv6_addresses))

    def _validate_attribute_value(self, attribute_value):
        if len(attribute_value) > self._max_string_length:
            attribute_value = attribute_value[:self._max_string_length] + '...'
        return attribute_value

    def _get_port_duplex(self):
        duplex = None
        snmp_result = self._get_snmp_attribute(self.ETHERLIKE_MIB, 'dot3StatsDuplexStatus')
        if snmp_result:
            port_duplex = snmp_result.strip('\'')
            if re.search(r'[Ff]ull', port_duplex):
                duplex = 'Full'
            else:
                duplex = 'Half'
        return duplex

    def _get_port_autoneg(self):
        # auto_negotiation = self._snmp_service.snmp_request(('MAU-MIB', 'ifMauAutoNegAdminStatus'))
        # return auto_negotiation
        return False

    def get_port(self):
        """
        Build Port instance using collected information
        :return:
        """
        port = self._resource_model.entities.Port(self.index,
                                                  name=AddRemoveVlanHelper.convert_port_name(self.port_name))

        port.port_description = self.port_description
        port.l2_protocol_type = self.type
        port.mac_address = self._get_snmp_attribute(self.IF_MIB, 'ifPhysAddress')
        port.mtu = self._get_snmp_attribute(self.IF_MIB, 'ifMtu')
        port.bandwidth = self._get_snmp_attribute(self.IF_MIB, 'ifHighSpeed')
        port.ipv4_address = self._get_associated_ipv4_address()
        port.ipv6_address = self._get_associated_ipv6_address()
        port.duplex = self._get_port_duplex()
        port.auto_negotiation = self._get_port_autoneg()
        port.adjacent = self.port_adjacent

        return port

    def get_portchannel(self):
        """
        Build PortChannel instance using collected information
        :return:
        """
        port_channel = self._resource_model.entities.PortChannel(self.port_phis_id,
                                                                 name=AddRemoveVlanHelper.convert_port_name(
                                                                     self.port_name))

        port_channel.port_description = self.port_description
        port_channel.ipv4_address = self._get_associated_ipv4_address()
        port_channel.ipv6_address = self._get_associated_ipv6_address()
        port_channel.associated_ports = ','.join(self.associated_port_names)

        return port_channel
