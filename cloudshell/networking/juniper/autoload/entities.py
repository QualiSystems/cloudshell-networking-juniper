import re
import sys

from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject

from cloudshell.networking.juniper.autoload.mib_names import MIBS
from cloudshell.networking.juniper.helpers.add_remove_vlan_helper import (
    AddRemoveVlanHelper,
)

if sys.version_info >= (3, 0):
    from functools import lru_cache
else:
    from functools32 import lru_cache


class JuniperGenericPort(object):
    """Collect information and build Port or PortChannel."""

    PORTCHANNEL_NAME_PATTERN = re.compile(r"ae(\d+)", re.IGNORECASE)
    AUTOLOAD_MAX_STRING_LENGTH = 100

    def __init__(self, index, snmp_service, resource_model):
        """Create GenericPort with index and snmp handler.

        :param int index:
        :param cloudshell.snmp.core.snmp_service.SnmpService snmp_service:
        :param  resource_model:
        :type resource_model: cloudshell.shell.standards.networking.autoload_model.NetworkingResourceModel|cloudshell.shell.standards.firewall.autoload_model.FirewallResourceModel  # noqa
        """
        self.index = index
        self._snmp_service = snmp_service
        self._resource_model = resource_model

        self.associated_port_names = []
        self.ipv4_addresses = []
        self.ipv6_addresses = []
        self.port_adjacent = None

        self._max_string_length = self.AUTOLOAD_MAX_STRING_LENGTH

    def _get_snmp_attribute(self, mib, snmp_attribute):
        return self._snmp_service.get_property(
            SnmpMibObject(mib, snmp_attribute, self.index)
        ).safe_value

    @property
    @lru_cache()
    def port_phis_id(self):
        return self._get_snmp_attribute(MIBS.JUNIPER_IF_MIB, "ifChassisPort")

    @property
    @lru_cache()
    def port_description(self):
        return self._get_snmp_attribute("IF-MIB", "ifAlias")

    @property
    @lru_cache()
    def logical_unit(self):
        return self._get_snmp_attribute(MIBS.JUNIPER_IF_MIB, "ifChassisLogicalUnit")

    @property
    @lru_cache()
    def fpc_id(self):
        return self._get_snmp_attribute(MIBS.JUNIPER_IF_MIB, "ifChassisFpc")

    @property
    @lru_cache()
    def pic_id(self):
        return self._get_snmp_attribute(MIBS.JUNIPER_IF_MIB, "ifChassisPic")

    @property
    @lru_cache()
    def port_type(self):
        return self._get_snmp_attribute(MIBS.IF_MIB, "ifType").strip("'")

    @property
    @lru_cache()
    def port_name(self):
        return self._get_snmp_attribute(
            MIBS.IF_MIB, "ifDescr"
        ) or self._get_snmp_attribute(MIBS.IF_MIB, "ifName")

    @property
    def is_portchannel(self):
        return (
            True if re.match(self.PORTCHANNEL_NAME_PATTERN, self.port_name) else False
        )

    @property
    def _portchannel_index(self):
        match = re.match(self.PORTCHANNEL_NAME_PATTERN, self.port_name)
        if match:
            return match.group(1)
        else:
            return None

    def _get_associated_ipv4_address(self):
        return self._validate_attribute_value(",".join(self.ipv4_addresses))

    def _get_associated_ipv6_address(self):
        return self._validate_attribute_value(",".join(self.ipv6_addresses))

    def _validate_attribute_value(self, attribute_value):
        if len(attribute_value) > self._max_string_length:
            attribute_value = attribute_value[: self._max_string_length] + "..."
        return attribute_value

    def _get_port_duplex(self):
        duplex = None
        snmp_result = self._get_snmp_attribute(
            MIBS.ETHERLIKE_MIB, "dot3StatsDuplexStatus"
        )
        if snmp_result:
            port_duplex = snmp_result.strip("'")
            if re.search(r"[Ff]ull", port_duplex):
                duplex = "Full"
            else:
                duplex = "Half"
        return duplex

    def _get_port_autoneg(self):
        # auto_negotiation = self._snmp_service.snmp_request(('MAU-MIB', 'ifMauAutoNegAdminStatus'))  # noqa
        # return auto_negotiation  # noqa
        return False

    def get_port(self):
        """Build Port instance using collected information.

        :return:
        """
        port = self._resource_model.entities.Port(
            self.port_phis_id,
            name=AddRemoveVlanHelper.convert_port_name(self.port_name),
        )

        port.port_description = self.port_description
        port.l2_protocol_type = self.port_type
        port.mac_address = self._get_snmp_attribute(MIBS.IF_MIB, "ifPhysAddress")
        port.mtu = self._get_snmp_attribute(MIBS.IF_MIB, "ifMtu")
        port.bandwidth = self._get_snmp_attribute(MIBS.IF_MIB, "ifHighSpeed")
        port.ipv4_address = self._get_associated_ipv4_address()
        port.ipv6_address = self._get_associated_ipv6_address()
        port.duplex = self._get_port_duplex()
        port.auto_negotiation = self._get_port_autoneg()
        port.adjacent = self.port_adjacent

        return port

    def get_portchannel(self):
        """Build PortChannel instance using collected information.

        :return:
        """
        port_channel = self._resource_model.entities.PortChannel(
            self._portchannel_index,
            name=AddRemoveVlanHelper.convert_port_name(self.port_name),
        )

        port_channel.port_description = self.port_description
        port_channel.ipv4_address = self._get_associated_ipv4_address()
        port_channel.ipv6_address = self._get_associated_ipv6_address()
        port_channel.associated_ports = ",".join(self.associated_port_names)

        return port_channel
