#!/usr/bin/python
# -*- coding: utf-8 -*-
from cloudshell.networking.juniper.autoload.entities import JuniperGenericPort
from cloudshell.networking.juniper.autoload.mib_names import MIBS

import os
import re
from functools import reduce
from cloudshell.networking.juniper.autoload.utils import sort_elements_by_attributes
from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject


class JunosSnmpAutoload(object):
    """
    Load inventory by snmp and build device elements and attributes
    """
    FILTER_PORTS_BY_DESCRIPTION = ['bme', 'vme', 'me', 'vlan', 'gr', 'vt', 'mt', 'mams', 'irb', 'lsi', 'tap', 'fxp']
    FILTER_PORTS_BY_TYPE = ['tunnel', 'other', 'pppMultilinkBundle', 'mplsTunnel', 'softwareLoopback']

    SNMP_ERRORS = [r'No\s+Such\s+Object\s+currently\s+exists']

    def __init__(self, snmp_service, logger):
        """
        :param cloudshell.snmp.core.snmp_service.SnmpService snmp_service:
        :param logging.Logger logger:
        """
        self._snmp_service = snmp_service
        self._logger = logger

        self._content_indexes = None
        self._if_indexes = None
        self._initialize_snmp_handler()

        self._chassis = {}
        self._modules = {}
        self.sub_modules = {}
        self._ports = {}
        self._logical_generic_ports = {}
        self._physical_generic_ports = {}
        self._generic_physical_ports_by_name = None
        self._generic_logical_ports_by_name = None

        self._ipv4_table = None
        self._ipv6_table = None
        self._if_duplex_table = None
        self._autoneg = None
        self._lldp_keys = None
        self._power_port_indexes = []
        self._chassis_indexes = []

    @property
    def ipv4_table(self):
        if not self._ipv4_table:
            self._ipv4_table = sort_elements_by_attributes(
                self._snmp_service.walk(('IP-MIB', 'ipAddrTable')), 'ipAdEntIfIndex')
        return self._ipv4_table

    @property
    def ipv6_table(self):
        if not self._ipv6_table:
            self._ipv6_table = sort_elements_by_attributes(
                self._snmp_service.walk(('IPV6-MIB', 'ipv6AddrEntry')), 'ipAdEntIfIndex')
        return self._ipv6_table

    @property
    def generic_physical_ports_by_name(self):
        if not self._generic_physical_ports_by_name:
            self._generic_physical_ports_by_name = {}
            for index, generic_port in self._physical_generic_ports.items():
                self._generic_physical_ports_by_name[generic_port.port_name] = generic_port
        return self._generic_physical_ports_by_name

    @property
    def generic_logical_ports_by_name(self):
        if not self._generic_logical_ports_by_name:
            self._generic_logical_ports_by_name = {}
            for index, generic_port in self._logical_generic_ports.items():
                self._generic_logical_ports_by_name[generic_port.port_name] = generic_port
        return self._generic_logical_ports_by_name

    def _build_lldp_keys(self):
        result_dict = {}
        try:
            keys = self._snmp_service.walk(('LLDP-MIB', 'lldpRemPortId')).keys()
        except:
            keys = []
        for key in keys:
            key_splited = str(key).split('.')
            if len(key_splited) == 3:
                result_dict[key_splited[1]] = key
            elif len(key_splited) == 1:
                result_dict[key_splited[0]] = key
        return result_dict

    @property
    def lldp_keys(self):
        if not self._lldp_keys:
            self._lldp_keys = self._build_lldp_keys()
        return self._lldp_keys

    @property
    def device_info(self):
        system_description = self._snmp_service.get_property(SnmpMibObject('SNMPv2-MIB', 'sysDescr', '0'))
        system_description += self._snmp_service.get_property(SnmpMibObject('JUNIPER-MIB', 'jnxBoxDescr', '0'))
        return system_description

    def _initialize_snmp_handler(self):
        """
        Snmp settings and load specific mibs
        :return:
        """
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mibs'))
        self._snmp_service.add_mib_folder_path(path)
        self._logger.info("Loading mibs")
        self._snmp_service.load_mib_tables(
            [MIBS.JUNIPER_MIB, MIBS.JUNIPER_IF_MIB, MIBS.IF_MIB, MIBS.LAG_MIB, MIBS.IP_MIB, MIBS.IPV6_MIB,
             MIBS.LLDP_MIB])

    def build_root(self, resource_model):
        """
        Collect device root attributes
        :return:
        """
        self._logger.info("Building Root")
        vendor = ''
        model = ''
        os_version = ''
        sys_obj_id = self._snmp_service.get_property(SnmpMibObject(MIBS.SNMPV2_MIB, 'sysObjectID', '0'))
        model_search = re.search(r'^(?P<vendor>\w+)-\S+jnxProduct(?:Name)?(?P<model>\S+)', sys_obj_id)
        if model_search:
            vendor = model_search.groupdict()['vendor'].capitalize()
            model = model_search.groupdict()['model']
        os_version_search = re.search(r'JUNOS \S+(,)?\s', self.device_info, re.IGNORECASE)
        if os_version_search:
            os_version = os_version_search.group(0).replace('JUNOS ', '').replace(',', '').strip(' \t\n\r')

        resource_model.contact_name = self._snmp_service.get_property(SnmpMibObject('SNMPv2-MIB', 'sysContact', '0'))
        resource_model.system_name = self._snmp_service.get_property(SnmpMibObject('SNMPv2-MIB', 'sysName', '0'))
        resource_model.location = self._snmp_service.get_property(SnmpMibObject('SNMPv2-MIB', 'sysLocation', '0'))
        resource_model.os_version = os_version
        resource_model.vendor = vendor
        resource_model.model = model
        return resource_model

    def _get_content_indexes(self):
        container_indexes = self._snmp_service.walk(('JUNIPER-MIB', 'jnxContentsContainerIndex'))
        content_indexes = {}
        for index, value in container_indexes.iteritems():
            ct_index = value['jnxContentsContainerIndex']
            if ct_index in content_indexes:
                content_indexes[ct_index].append(index)
            else:
                content_indexes[ct_index] = [index]
        return content_indexes

    @property
    def content_indexes(self):
        if not self._content_indexes:
            self._content_indexes = self._get_content_indexes()
        return self._content_indexes

    @property
    def if_indexes(self):
        if not self._if_indexes:
            self._if_indexes = self._snmp_service.walk(('JUNIPER-IF-MIB', 'ifChassisPort')).keys()
        return self._if_indexes

    def build_chassis(self, resource_model):
        """
        Build Chassis resources and attributes
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis]
        """
        self._logger.debug('Building Chassis')
        element_index = '1'
        chassis_snmp_attributes = {'jnxContentsModel': 'str', 'jnxContentsType': 'str', 'jnxContentsSerialNo': 'str',
                                   'jnxContentsChassisId': 'str'}
        chassis_table = {}
        if element_index in self.content_indexes:
            for index in self.content_indexes[element_index]:
                content_data = self._snmp_service.get_properties('JUNIPER-MIB', index, chassis_snmp_attributes).get(
                    index)
                index1, index2, index3, index4 = index.split('.')[:4]
                chassis_id = index2

                if chassis_id in self._chassis_indexes:
                    continue

                self._chassis_indexes.append(chassis_id)

                chassis = resource_model.entities.Chassis(index)
                chassis.model = self._get_element_model(content_data)
                chassis.serial_number = content_data.get("jnxContentsSerialNo")

                resource_model.connect_chassis(chassis)

                chassis_id_str = content_data.get("jnxContentsChassisId")
                if chassis_id_str:
                    chassis_table[chassis_id_str.strip("'")] = chassis
        return chassis_table

    def build_power_modules(self, resource_model, chassis_table):
        """
        Build Power modules resources and attributes
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericPowerPort]
        """
        self._logger.debug("Building PowerPorts")
        power_modules_snmp_attributes = {"jnxContentsModel": "str", "jnxContentsType": "str", "jnxContentsDescr": "str",
                                         "jnxContentsSerialNo": "str", "jnxContentsRevision": "str",
                                         "jnxContentsChassisId": "str"}
        element_index = "2"
        power_port_table = {}
        if element_index in self.content_indexes:
            for index in self.content_indexes[element_index]:
                content_data = self._snmp_service.get_properties("JUNIPER-MIB", index,
                                                                 power_modules_snmp_attributes).get(index)
                index1, index2, index3, index4 = index.split(".")[:4]

                power_port_id = index2
                if power_port_id in self._power_port_indexes:
                    continue
                self._power_port_indexes.append(power_port_id)

                power_port = resource_model.entities.PowerPort(index)

                power_port.model = self._get_element_model(content_data)
                power_port.port_description = content_data.get("jnxContentsDescr")
                power_port.serial_number = content_data.get("jnxContentsSerialNo")
                power_port.version = content_data.get("jnxContentsRevision")

                chassis_id_str = content_data.get("jnxContentsChassisId")
                if chassis_id_str:
                    chassis = chassis_table.get(chassis_id_str.strip("'"))
                    if chassis:
                        chassis.connect_power_port(power_port)
                        power_port_table[power_port_id] = power_port
        return power_port_table

    def build_modules(self, resource_model, chassis_table):
        """
        Build Modules resources and attributes
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule]
        """
        self._logger.debug("Building Modules")
        modules_snmp_attributes = {"jnxContentsModel": "str",
                                   "jnxContentsType": "str",
                                   "jnxContentsSerialNo": "str",
                                   "jnxContentsRevision": "str",
                                   "jnxContentsChassisId": "str"}
        element_index = "7"
        module_table = {}
        if element_index in self.content_indexes:
            for index in self.content_indexes[element_index]:
                content_data = self._snmp_service.get_properties("JUNIPER-MIB", index,
                                                                 modules_snmp_attributes).get(index)
                index1, index2, index3, index4 = index.split(".")[:4]
                module_id = index2

                if module_id in module_table or int(module_id) == 0:
                    continue

                module = resource_model.entities.Module(module_id)

                module.model = self._get_element_model(content_data)
                module.serial_number = content_data.get("jnxContentsSerialNo")
                module.version = content_data.get("jnxContentsRevision")

                chassis_id_str = content_data.get("jnxContentsChassisId")
                if chassis_id_str:
                    chassis = chassis_table.get(chassis_id_str.strip("'"))
                    if chassis:
                        chassis.connect_module(module)
                        module_table['.'.join([module_id, '0'])] = module
        return module_table

    def build_sub_modules(self, resource_model, module_table):
        """
        Build SubModules resources and attributes
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule] module_table:
        :rtype: dict[str, cloudshell.shell.standards.autoload_generic_models.GenericSubModule]
        """
        self._logger.debug("Building Sub Modules")
        sub_modules_snmp_attributes = {"jnxContentsModel": "str",
                                       "jnxContentsType": "str",
                                       "jnxContentsSerialNo": "str",
                                       "jnxContentsRevision": "str"}

        element_indexes = ["8", "20"]
        sub_module_table = {}
        for index in reduce(lambda x, y: x + self.content_indexes.get(y, []), element_indexes, []):
            content_data = self._snmp_service.get_properties("JUNIPER-MIB", index,
                                                             sub_modules_snmp_attributes).get(index)
            index1, index2, index3, index4 = index.split(".")[:4]
            module_id = index2
            sub_module_id = index3

            if int(module_id) == 0 or int(sub_module_id) == 0:
                continue

            sub_module = resource_model.entities.SubModule(sub_module_id)

            sub_module.model = self._get_element_model(content_data)
            sub_module.serial_number = content_data.get("jnxContentsSerialNo")
            sub_module.version = content_data.get("jnxContentsRevision")

            module = module_table.get(str(module_id))
            if module:
                module.connect_sub_module(sub_module)
                sub_module_table['.'.join([module_id, sub_module_id])] = sub_module
        return sub_module_table

    @staticmethod
    def _get_element_model(content_data):
        model_string = content_data.get('jnxContentsModel')
        if not model_string:
            model_string = content_data.get('jnxContentsType').split('::')[-1]
        return model_string

    def _build_generic_ports(self, resource_model):
        """
        Build JuniperGenericPort instances
        :return:
        """
        self._logger.debug("Building generic ports")

        for index in self.if_indexes:
            index = int(index)
            generic_port = JuniperGenericPort(index, self._snmp_service, resource_model)
            if not self._port_filtered_by_name(generic_port) and not self._port_filtered_by_type(generic_port):
                if generic_port.logical_unit == '0':
                    self._physical_generic_ports[index] = generic_port
                else:
                    self._logical_generic_ports[index] = generic_port

    def _associate_ipv4_addresses(self):
        """
        Associates ipv4 with generic port
        :return:
        """
        self._logger.debug("Associate ipv4")
        for index in self.ipv4_table:
            if int(index) in self._logical_generic_ports:
                logical_port = self._logical_generic_ports[int(index)]
                physical_port = self.get_associated_phisical_port_by_name(logical_port.port_name)
                ipv4_address = self.ipv4_table[index].get('ipAdEntAddr')
                if physical_port and ipv4_address:
                    physical_port.ipv4_addresses.append(ipv4_address)

    def _associate_ipv6_addresses(self):
        """
        Associate ipv6 with generic port
        :return:
        """
        self._logger.debug("Associate ipv6")
        for index in self.ipv6_table:
            if int(index) in self._logical_generic_ports:
                logical_port = self._logical_generic_ports[int(index)]
                physical_port = self.get_associated_phisical_port_by_name(logical_port.port_name)
                ipv6_address = self.ipv6_table[index].get('ipAdEntAddr')
                if ipv6_address:
                    physical_port.ipv6_addresses.append(ipv6_address)

    def _associate_portchannels(self):
        """
        Associate physical ports with the portchannel
        :return:
        """
        self._logger.debug("Associate portchannels")
        snmp_data = self._snmp_service.walk(('IEEE8023-LAG-MIB', 'dot3adAggPortAttachedAggID'))
        for port_index in snmp_data:
            port_index = int(port_index)
            if port_index in self._logical_generic_ports:
                associated_phisical_port = self.get_associated_phisical_port_by_name(
                    self._logical_generic_ports[port_index].port_name)
                logical_portchannel_index = snmp_data[port_index].get('dot3adAggPortAttachedAggID')
                if logical_portchannel_index and int(logical_portchannel_index) in self._logical_generic_ports:
                    associated_phisical_portchannel = self.get_associated_phisical_port_by_name(
                        self._logical_generic_ports[int(logical_portchannel_index)].port_name)
                    if associated_phisical_portchannel:
                        associated_phisical_portchannel.is_portchannel = True
                        if associated_phisical_port:
                            associated_phisical_portchannel.associated_port_names.append(associated_phisical_port.name)

    def _associate_adjacent(self):
        for index in self.lldp_keys:
            if int(index) in self._logical_generic_ports:
                physical_port = self.get_associated_phisical_port_by_name(
                    self._logical_generic_ports[int(index)].port_name)
                self._set_adjacent(index, physical_port)
            elif int(index) in self._physical_generic_ports:
                physical_port = self._physical_generic_ports[int(index)]
                self._set_adjacent(index, physical_port)

    def _set_adjacent(self, index, port):
        rem_port_descr = self._snmp_service.get_property('LLDP-MIB', 'lldpRemPortDesc', self.lldp_keys[index])
        rem_sys_descr = self._snmp_service.get_property('LLDP-MIB', 'lldpRemSysDesc', self.lldp_keys[index])
        port.port_adjacent = '{0}, {1}'.format(rem_port_descr, rem_sys_descr)

    def get_associated_phisical_port_by_name(self, description):
        """
        Associate physical port by description
        :param description:
        :return:
        """
        for port_name in self.generic_physical_ports_by_name:
            if port_name in description:
                return self.generic_physical_ports_by_name[port_name]
        return None

    def _port_filtered_by_name(self, port):
        """
        Filter ports by description
        :param port:
        :return:
        """
        for pattern in self.FILTER_PORTS_BY_DESCRIPTION:
            if re.search(pattern, port.port_name):
                return True
        return False

    def _port_filtered_by_type(self, port):
        """
        Filter ports by type
        :param port:
        :return:
        """
        if port.type in self.FILTER_PORTS_BY_TYPE:
            return True
        return False

    def build_ports(self, resource_model, chassis_table, module_table, sub_module_table):
        """
        Associate ports with the structure resources and build Ports and PortChannels
        :param resource_model:
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericChassis] chassis_table:
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericModule] module_table:
        :param dict[str, cloudshell.shell.standards.autoload_generic_models.GenericSubModule] sub_module_table:
        :rtype: dict
        """
        self._logger.debug("Building ports")
        self._build_generic_ports(resource_model)
        self._associate_ipv4_addresses()
        self._associate_ipv6_addresses()
        self._associate_portchannels()
        self._associate_adjacent()

        parent_table = {**module_table, **sub_module_table}
        port_table = {}
        for generic_port in self._physical_generic_ports.values():
            generic_port = generic_port
            """:type generic_port: JuniperGenericPort"""
            if generic_port.is_portchannel:
                resource_model.connect_port_channel(generic_port.get_portchannel())
            else:
                port = generic_port.get_port()
                parent = parent_table.get('.'.join([generic_port.fpc_id, generic_port.pic_id]),
                                          list(chassis_table.values())[0])
                parent.connect_port(port)
        return port_table
