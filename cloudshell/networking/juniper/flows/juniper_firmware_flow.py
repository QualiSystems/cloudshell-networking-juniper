from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from cloudshell.cli.service.cli_service import CliService
from cloudshell.shell.flows.firmware.basic_flow import AbstractFirmwareFlow

from cloudshell.networking.juniper.command_actions.system_actions import SystemActions

if TYPE_CHECKING:
    from typing import Union

    from cloudshell.shell.flows.utils.url import BasicLocalUrl, RemoteURL
    from cloudshell.shell.standards.networking.resource_config import (
        NetworkingResourceConfig,
    )

    from ..cli.juniper_cli_configurator import JuniperCliConfigurator

    Url = Union[RemoteURL, BasicLocalUrl]


logger = logging.getLogger(__name__)


class JuniperFirmwareFlow(AbstractFirmwareFlow):
    def __init__(
        self,
        resource_config: NetworkingResourceConfig,
        cli_configurator: JuniperCliConfigurator,
    ):
        super().__init__(resource_config)
        self.cli_configurator = cli_configurator

    def _load_firmware_flow(
        self,
        firmware_url: Url,
        vrf_management_name: str | None,
        timeout: int,
    ) -> None:
        """Load firmware.

        Update firmware version on device by loading provided
        image, performs following steps:
            1. Copy bin file from remote tftp server.
            2. Clear in run config boot system section.
            3. Set downloaded bin file as boot file and then reboot device.
            4. Check if firmware was successfully installed.

        :param path: full path to firmware file on ftp/tftp location
        :param vrf_management_name: VRF Name
        """
        logger.info("Upgrading firmware")
        with self.cli_configurator.enable_mode_service() as cli_service:
            system_actions = SystemActions(cli_service)
            system_actions.load_firmware(str(firmware_url), timeout=timeout)
            waiting_time = 0
            try:
                system_actions.reboot(20)
                logger.debug("Waiting session down")
                waiting_time = self._wait_session_disconnect(cli_service, timeout)
            except Exception:
                pass
            logger.debug("Waiting session up")
            cli_service.reconnect(timeout - waiting_time)

    def _wait_session_disconnect(self, cli_service: CliService, timeout: int):
        reboot_time = time.time()
        while True:
            rest_time = time.time() - reboot_time
            try:
                if rest_time > timeout:
                    raise Exception(
                        self.__class__.__name__,
                        f"Session cannot start reboot after {timeout} sec.",
                    )
                cli_service.send_command("", timeout=10)
                time.sleep(1)
            except Exception:
                logger.debug("Session disconnected")
                return rest_time
