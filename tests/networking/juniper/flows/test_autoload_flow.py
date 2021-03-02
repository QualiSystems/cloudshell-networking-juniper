from unittest import TestCase

from cloudshell.networking.juniper.flows.autoload_flow import JunOSAutoloadFlow

try:
    from unittest.mock import MagicMock, patch
except ImportError:
    from mock import MagicMock, patch


class TestAutoloadFlow(TestCase):
    def setUp(self):
        self._snmp_configurator = MagicMock()
        self._logger = MagicMock()
        self._autoload_flow = JunOSAutoloadFlow(self._snmp_configurator, self._logger)

    def test_autoload_flow(self):
        resource_model = MagicMock()
        with patch(
            "cloudshell.networking.juniper.flows.autoload_flow." "JunosSnmpAutoload"
        ) as autoload_class_mock:
            autoload_mock = autoload_class_mock()
            autoload_mock.device_info = "Junos"
            self._autoload_flow._autoload_flow(["Junos"], resource_model)

            autoload_mock.build_root.assert_called_once_with(resource_model)
            autoload_mock.build_chassis.assert_called_once_with(resource_model)
            chassis_table = autoload_mock.build_chassis()
            autoload_mock.build_power_modules(resource_model, chassis_table)
            autoload_mock.build_modules.assert_called_once_with(
                resource_model, chassis_table
            )
            module_table = autoload_mock.build_modules()
            autoload_mock.build_sub_modules.assert_called_once_with(
                resource_model, module_table
            )
            sub_module_table = autoload_mock.build_sub_modules()
            autoload_mock.build_ports.assert_called_once_with(
                resource_model, chassis_table, module_table, sub_module_table
            )
            resource_model.build.assert_called_once_with(
                filter_empty_modules=True, use_new_unique_id=True
            )

    def test_autoload_flow_not_supported_version(self):
        resource_model = MagicMock()
        with patch(
            "cloudshell.networking.juniper.flows.autoload_flow." "JunosSnmpAutoload"
        ) as autoload_class_mock:
            autoload_mock = autoload_class_mock()
            autoload_mock.device_info = "Another"
            with self.assertRaisesRegexp(Exception, "Unsupported device OS"):
                self._autoload_flow._autoload_flow(["Junos"], resource_model)
