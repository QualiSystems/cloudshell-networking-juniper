from __future__ import annotations
from typing import TYPE_CHECKING

from cloudshell.cli.session.session_exceptions import CommandExecutionException
from cloudshell.shell.flows.configuration.basic_flow import AbstractConfigurationFlow, ConfigurationType, RestoreMethod

from cloudshell.networking.juniper.command_actions.commit_rollback_actions import (
    CommitRollbackActions,
)
from cloudshell.networking.juniper.command_actions.save_restore_actions import (
    SaveRestoreActions,
)
from cloudshell.networking.juniper.helpers.errors import (
    NotSupportedJunOSError,
)

if TYPE_CHECKING:
    from typing import Set, Union
    from logging import Logger
    from cloudshell.shell.flows.utils.url import RemoteURL, BasicLocalUrl
    from cloudshell.shell.standards.networking.resource_config import NetworkingResourceConfig
    from ..cli.juniper_cli_configurator import JuniperCliConfigurator
    Url = Union[RemoteURL, BasicLocalUrl]


class JuniperConfigurationFlow(AbstractConfigurationFlow):
    SUPPORTED_CONFIGURATION_TYPES: Set[ConfigurationType] = {
        ConfigurationType.RUNNING,
    }
    SUPPORTED_RESTORE_METHODS: Set[RestoreMethod] = {
        RestoreMethod.OVERRIDE,
        RestoreMethod.APPEND,
    }

    def __init__(self, resource_config: NetworkingResourceConfig, logger: Logger, cli_configurator: JuniperCliConfigurator):
        super(JuniperConfigurationFlow, self).__init__(logger, resource_config)
        self.cli_configurator = cli_configurator

    @property
    def file_system(self)->str:
        return "local:"

    def _save_flow(self, file_dst_url: Url, configuration_type: ConfigurationType, vrf_management_name: str | None)->None:
        """Backup config.

        Backup 'startup-config' or 'running-config' from
        device to provided file_system [ftp|tftp].
        Also possible to backup config to localhost
        :param file_dst_url: destination url, remote or local, where file will be saved
        :param configuration_type: type of configuration
        that will be saved (StartUp or Running)
        :param vrf_management_name: Virtual Routing and
        Forwarding management name
]        """
        if file_dst_url.scheme == "tftp":
            raise NotSupportedJunOSError("TFTP is not supported by JunOS")

        self._logger.info("Save configuration to {0}".format(file_dst_url))

        with self.cli_configurator.config_mode_service() as cli_service:
            save_action = SaveRestoreActions(cli_service, self._logger)
            password = file_dst_url.password
            file_dst_url.password = None
            save_action.save_running(
                str(file_dst_url), password
            )

    def _restore_flow(
        self,
        config_path: Url,
        configuration_type: ConfigurationType,
        restore_method: RestoreMethod,
        vrf_management_name: str | None,
    )->None:
        """Restore configuration on device from provided configuration file.

        Restore configuration from local file system or ftp/tftp
        server into 'running-config' or 'startup-config'.
        :param config_path: relative path to the file on the
        remote host tftp://server/sourcefile
        :param configuration_type: the configuration
        type to restore (StartUp or Running)
        :param restore_method: override current config or not
        :param vrf_management_name: Virtual Routing and
        Forwarding management name
        """
        if config_path.scheme == "tftp":
            raise NotSupportedJunOSError("TFTP is not supported by JunOS")

        if restore_method == RestoreMethod.APPEND:
            restore_type = "merge"
        else:
            restore_type = "override"

        with self.cli_configurator.config_mode_service() as cli_service:
            restore_actions = SaveRestoreActions(cli_service, self._logger)
            commit_rollback_actions = CommitRollbackActions(cli_service, self._logger)

            password = config_path.password
            config_path.password = None
            try:
                restore_actions.restore_running(
                    restore_type, str(config_path), password
                )
                # wait longer for applying changes
                commit_rollback_actions.commit(timeout=120)
            except CommandExecutionException:
                commit_rollback_actions.rollback()
                raise
