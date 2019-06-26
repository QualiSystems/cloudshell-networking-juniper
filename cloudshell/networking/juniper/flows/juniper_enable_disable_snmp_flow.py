from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.networking.juniper.command_actions.commit_rollback_actions import CommitRollbackActions
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions import EnableDisableSnmpActions
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_v3_actions import EnableDisableSnmpV3Actions
from cloudshell.snmp.snmp_configurator import EnableDisableSnmpFlowInterface
from cloudshell.snmp.snmp_parameters import SNMPV3Parameters


class JuniperEnableDisableSnmpFlow(EnableDisableSnmpFlowInterface):
    def __init__(self, cli_configurator, logger):
        """
        Enable Disable snmp flow
        :param cloudshell.shell.standards.resource_config_generic_models.GenericSnmpConfig resource_config:
        :param cloudshell.networking.juniper.cli.juniper_cli_configurator.JuniperCliConfigurator cli_configurator:
        :param logging.Logger logger:
        :return:
        """

        # super(JuniperEnableDisableSnmpFlow, self).__init__(cli_handler, logger)
        # self._cli_handler = cli_handler
        self._cli_configurator = cli_configurator
        self._logger = logger

    def enable_snmp(self, snmp_parameters):
        with self._cli_configurator.config_mode_service() as cli_service:
            if isinstance(snmp_parameters, SNMPV3Parameters):
                self._enable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._enable_snmp(cli_service, snmp_parameters)

    def _enable_snmp(self, cli_service, snmp_parameters):
        """
        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param cloudshell.snmp.snmp_parameters.SNMPV1Parameters snmp_parameters:
        """
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        if not snmp_actions.configured(snmp_community):
            self._logger.debug('Configuring SNMP with community {}'.format(snmp_community))
            try:
                output = snmp_actions.enable_snmp(snmp_community,
                                                  write=snmp_parameters.is_read_only is False)
                output += commit_rollback.commit()
                return output
            except CommandExecutionException:
                commit_rollback.rollback()
                self._logger.exception('Failed to enable SNMP')
                raise

    def _enable_snmp_v3(self, cli_service, snmp_parameters):
        """
        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param snmp_parameters: cloudshell.snmp.snmp_parameters.SNMPV3Parameters
        """
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        snmp_user = snmp_parameters.snmp_user
        snmp_password = snmp_parameters.snmp_password
        snmp_priv_key = snmp_parameters.snmp_private_key
        snmp_auth_proto = snmp_parameters.auth_protocol
        snmp_priv_proto = snmp_parameters.private_key_protocol
        self._logger.debug('Enable SNMPv3')
        try:
            output = snmp_v3_actions.enable_snmp_v3(snmp_user, snmp_password, snmp_priv_key, snmp_auth_proto,
                                                    snmp_priv_proto)
            commit_rollback.commit()
            return output
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception('Failed to enable SNMPv3')
            raise

    def disable_snmp(self, snmp_parameters):
        with self._cli_configurator.config_mode_service() as cli_service:
            if isinstance(snmp_parameters, SNMPV3Parameters):
                self._disable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._disable_snmp(cli_service, snmp_parameters)

    def _disable_snmp(self, cli_service, snmp_parameters):
        """
        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param cloudshell.snmp.snmp_parameters.SNMPV1Parameters snmp_parameters:
        """
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        try:
            self._logger.debug('Disable SNMP')
            snmp_actions.disable_snmp(snmp_community)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception('Failed to disable SNMP')
            raise

    def _disable_snmp_v3(self, cli_service, snmp_parameters):
        """
        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param snmp_parameters: cloudshell.snmp.snmp_parameters.SNMPV3Parameters
        """
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        snmp_user = snmp_parameters.snmp_user
        try:
            self._logger.debug('Disable SNMPv3')
            snmp_v3_actions.disable_snmp_v3(snmp_user)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception('Failed to enable SNMPv3')
            raise
