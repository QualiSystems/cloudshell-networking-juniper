from __future__ import annotations
from typing import TYPE_CHECKING

from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.snmp.snmp_configurator import EnableDisableSnmpFlowInterface

from cloudshell.networking.juniper.command_actions.commit_rollback_actions import (
    CommitRollbackActions,
)
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_actions import (
    EnableDisableSnmpActions,
)
from cloudshell.networking.juniper.command_actions.enable_disable_snmp_v3_actions import (  # noqa
    EnableDisableSnmpV3Actions,
)

if TYPE_CHECKING:
    from typing import Union
    from logging import Logger
    from cloudshell.cli.service.cli_service import CliService
    from cloudshell.snmp.snmp_parameters import SNMPReadParameters, SNMPWriteParameters, SNMPV3Parameters
    from ..cli.juniper_cli_configurator import JuniperCliConfigurator

    SnmpParams = Union[SNMPReadParameters, SNMPWriteParameters, SNMPV3Parameters]


class JuniperEnableDisableSnmpFlow(EnableDisableSnmpFlowInterface):
    def __init__(self, cli_configurator: JuniperCliConfigurator, logger: Logger):
        """Enable Disable snmp flow."""
        self._cli_configurator = cli_configurator
        self._logger = logger

    def enable_snmp(self, snmp_parameters: SnmpParams) -> None:
        with self._cli_configurator.config_mode_service() as cli_service:
            if snmp_parameters.version == snmp_parameters.SnmpVersion.V3:
                self._enable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._enable_snmp(cli_service, snmp_parameters)

    def _enable_snmp(self, cli_service: CliService, snmp_parameters: SnmpParams)-> None:
        """Enable SNMPv1,2.

        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :type snmp_parameters: cloudshell.snmp.snmp_parameters.SNMPReadParameters|cloudshell.snmp.snmp_parameters.SNMPWriteParameters  # noqa
        """
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        if not snmp_actions.configured(snmp_community):
            self._logger.debug(
                "Configuring SNMP with community {}".format(snmp_community)
            )
            try:
                snmp_actions.enable_snmp(
                    snmp_community, write=snmp_parameters.is_read_only is False
                )
                commit_rollback.commit()
            except CommandExecutionException:
                commit_rollback.rollback()
                self._logger.exception("Failed to enable SNMP")
                raise

    def _enable_snmp_v3(self, cli_service: CliService, snmp_parameters: SnmpParams)->None:
        """Enable SNMPv3.

        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param snmp_parameters: cloudshell.snmp.snmp_parameters.SNMPV3Parameters
        """
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        snmp_user = snmp_parameters.snmp_user
        snmp_password = snmp_parameters.snmp_password
        snmp_priv_key = snmp_parameters.snmp_private_key
        snmp_auth_proto = snmp_parameters.snmp_auth_protocol
        snmp_priv_proto = snmp_parameters.snmp_private_key_protocol
        self._logger.debug("Enable SNMPv3")
        try:
            snmp_v3_actions.enable_snmp_v3(
                snmp_user,
                snmp_password,
                snmp_priv_key,
                snmp_auth_proto,
                snmp_priv_proto,
            )
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception("Failed to enable SNMPv3")
            raise

    def disable_snmp(self, snmp_parameters: SnmpParams)->None:
        with self._cli_configurator.config_mode_service() as cli_service:
            if snmp_parameters.version == snmp_parameters.SnmpVersion.V3:
                self._disable_snmp_v3(cli_service, snmp_parameters)
            else:
                self._disable_snmp(cli_service, snmp_parameters)

    def _disable_snmp(self, cli_service: CliService, snmp_parameters: SnmpParams)-> None:
        """Disable SNMPv1,2.

        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param cloudshell.snmp.snmp_parameters.SNMPReadParameters|cloudshell.snmp.snmp_parameters.SNMPWriteParameters snmp_parameters:  # noqa: E501
        """
        snmp_community = snmp_parameters.snmp_community
        if not snmp_community:
            raise Exception("SNMP Community has to be defined")
        snmp_actions = EnableDisableSnmpActions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        try:
            self._logger.debug("Disable SNMP")
            snmp_actions.remove_snmp_community(snmp_community)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception("Failed to remove SNMP community")
            raise
        try:
            snmp_actions.remove_snmp_view()
            commit_rollback.commit()
        except CommandExecutionException:
            # SNMPSHELLVIEW uses by other communities
            commit_rollback.rollback()

    def _disable_snmp_v3(self, cli_service: CliService, snmp_parameters: SnmpParams)->None:
        """Disable SNMPv3.

        :param cloudshell.cli.service.cli_service.CliService cli_service:
        :param snmp_parameters: cloudshell.snmp.snmp_parameters.SNMPV3Parameters
        """
        snmp_v3_actions = EnableDisableSnmpV3Actions(cli_service, self._logger)
        commit_rollback = CommitRollbackActions(cli_service, self._logger)
        snmp_user = snmp_parameters.snmp_user
        try:
            self._logger.debug("Disable SNMPv3")
            snmp_v3_actions.disable_snmp_v3(snmp_user)
            commit_rollback.commit()
        except CommandExecutionException:
            commit_rollback.rollback()
            self._logger.exception("Failed to enable SNMPv3")
            raise
