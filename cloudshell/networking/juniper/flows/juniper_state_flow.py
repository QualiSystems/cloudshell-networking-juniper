from cloudshell.shell.flows.state.basic_flow import StateFlow

from cloudshell.networking.juniper.command_actions.system_actions import SystemActions


class JuniperStateFlow(StateFlow):
    def shutdown(self):
        with self._cli_configurator.enable_mode_service() as cli_service:
            system_actions = SystemActions(cli_service, self._logger)
            return system_actions.shutdown()
