from cloudshell.networking.juniper.autoload.juniper_snmp_autoload import JuniperSnmpAutoload
from cloudshell.shell_flows.autoload.basic_flow import AbstractAutoloadFlow


class JuniperAutoload(AbstractAutoloadFlow):
    def __init__(self, snmp_handler, logger):
        super().__init__(logger)
        self._snmp_handler = snmp_handler

    def _autoload_flow(self, supported_os, resource_model):
        """
        :param supported_os:
        :param resource_model:
        :type resource_model: cloudshell.shell_standards.networking.autoload_model.NetworkingResourceModel|
        cloudshell.shell_standards.firewall.autoload_model.FirewallResourceModel
        :return:
        """
        return JuniperSnmpAutoload(self._snmp_handler, resource_model, self._logger).discover(
            supported_os)
