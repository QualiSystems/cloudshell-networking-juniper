from unittest import TestCase

from cloudshell.networking.juniper.helpers.add_remove_vlan_helper import (
    VlanRange,
    VlanRangeOperations,
    is_vlan_used,
)


class TestVlanRange(TestCase):
    def setUp(self):
        pass

    def test_init(self):
        first_id = "20"
        last_id = "50"
        instance = VlanRange((first_id, last_id))
        self.assertEqual(instance.first_element, int(first_id))
        self.assertEqual(instance.last_element, int(last_id))
        self.assertEqual(instance.name, "range-{0}-{1}".format(first_id, last_id))
        with self.assertRaises(Exception):
            VlanRange((30, 10))

    def test_intersect(self):
        first_id = "20"
        last_id = "50"
        instance = VlanRange((first_id, last_id))
        self.assertTrue(instance.intersect(VlanRange((10, 20))))
        self.assertTrue(instance.intersect(VlanRange((20, 50))))
        self.assertTrue(instance.intersect(VlanRange((50, 60))))
        self.assertTrue(instance.intersect(VlanRange((30, 40))))
        self.assertFalse(instance.intersect(VlanRange((5, 19))))
        self.assertFalse(instance.intersect(VlanRange((51, 60))))

    def test_cutoff(self):
        first_id = "50"
        last_id = "250"
        instance = VlanRange((first_id, last_id))
        self.assertEqual(instance.cutoff(VlanRange((20, 100))), [VlanRange((101, 250))])
        self.assertEqual(instance.cutoff(VlanRange((200, 300))), [VlanRange((50, 199))])
        self.assertEqual(instance.cutoff(VlanRange((50, 250))), [])
        self.assertEqual(
            instance.cutoff(VlanRange((70, 200))),
            [VlanRange((50, 69)), VlanRange((201, 250))],
        )
        self.assertEqual(instance.cutoff(VlanRange((300, 400))), [VlanRange((50, 250))])

    def test_range_from_string(self):
        self.assertEqual(
            VlanRange(VlanRange.range_from_string("10-20")), VlanRange((10, 20))
        )
        self.assertEqual(
            VlanRange(VlanRange.range_from_string("30")), VlanRange((30, 30))
        )

    def test_to_string(self):
        self.assertEqual(VlanRange((30, 40)).to_string(), "30-40")


class TestVlanRangeOperations(TestCase):
    def setUp(self):
        pass

    def test_create_from_dict(self):
        vlan_dict = {"test1": "10-20", "test2": "40-50"}
        range_list = VlanRangeOperations.create_from_dict(vlan_dict)
        self.assertEqual(set(range_list), {VlanRange((10, 20)), VlanRange((40, 50))})

    def test_cutoff_intersection(self):
        test_range = VlanRange((100, 500))
        result = VlanRangeOperations.cutoff_intersection(
            [test_range], [VlanRange((150, 200)), VlanRange((300, 350))]
        )
        self.assertEqual(
            result,
            [VlanRange((100, 149)), VlanRange((201, 299)), VlanRange((351, 500))],
        )

    def test_find_intersection(self):
        test_range = VlanRange((200, 300))
        range_list = [
            VlanRange((50, 100)),
            VlanRange((150, 200)),
            VlanRange((250, 270)),
            VlanRange((301, 400)),
        ]
        self.assertEqual(
            VlanRangeOperations.find_intersection([test_range], range_list),
            [VlanRange((150, 200)), VlanRange((250, 270))],
        )


class TestGetInterfacesWithVlanId(TestCase):
    COMMAND_OUTPUT = """<rpc-reply xmlns:junos="http://xml.juniper.net/junos/17.3R2/junos">
        <configuration junos:changed-seconds="0" junos:changed-localtime="0">
                <interfaces>
                    <interface>
                        <name>ge-0/0/0</name>
                        <unit>
                            <name>0</name>
                            <family>
                                <ethernet-switching unsupported="unsupported">
                                    <port-mode>access</port-mode>
                                    <vlan>
                                        <members>2-5</members>
                                        <members>7</members>
                                    </vlan>
                                </ethernet-switching>
                            </family>
                        </unit>
                    </interface>
                    <interface>
                        <name>ge-0/0/1</name>
                        <unit>
                            <name>0</name>
                            <family>
                                <ethernet-switching unsupported="unsupported">
                                    <port-mode>access</port-mode>
                                    <vlan>
                                        <members>2-5</members>
                                    </vlan>
                                </ethernet-switching>
                            </family>
                        </unit>
                    </interface>
                    <interface>
                        <name>fxp0</name>
                        <unit>
                            <name>0</name>
                            <family>
                                <inet>
                                    <address>
                                        <name>192.168.101.101/24</name>
                                    </address>
                                </inet>
                            </family>
                        </unit>
                    </interface>
                </interfaces>
        </configuration>
        <cli>
            <banner>[edit]</banner>
        </cli>
    </rpc-reply>
    """

    def test_interface_in_range(self):
        self.assertTrue(is_vlan_used("4", self.COMMAND_OUTPUT))
        self.assertTrue(is_vlan_used("2", self.COMMAND_OUTPUT))

    def test_interface_single_vlan(self):
        self.assertTrue(is_vlan_used("7", self.COMMAND_OUTPUT))

    def test_single_vlan_not_in_interfaces(self):
        self.assertFalse(is_vlan_used("6", self.COMMAND_OUTPUT))

    def test_vlan_range_intersect(self):
        self.assertTrue(is_vlan_used("3-4", self.COMMAND_OUTPUT))
        self.assertTrue(is_vlan_used("6-8", self.COMMAND_OUTPUT))

    def test_vlan_range_not_intersect(self):
        self.assertFalse(is_vlan_used("8-9", self.COMMAND_OUTPUT))

    def test_without_vlans(self):
        command_output = """<rpc-reply xmlns:junos="http://xml.juniper.net/junos/17.3R2/junos">
            <configuration junos:changed-seconds="0" junos:changed-localtime="0">
                    <interfaces>
                        <interface>
                            <name>ge-0/0/0</name>
                            <unit>
                                <name>0</name>
                                <family>
                                    <ethernet-switching unsupported="unsupported">
                                        <port-mode>access</port-mode>
                                    </ethernet-switching>
                                </family>
                            </unit>
                        </interface>
                        <interface>
                            <name>ge-0/0/1</name>
                            <unit>
                                <name>0</name>
                                <family>
                                    <ethernet-switching unsupported="unsupported">
                                        <port-mode>access</port-mode>
                                    </ethernet-switching>
                                </family>
                            </unit>
                        </interface>
                        <interface>
                            <name>fxp0</name>
                            <unit>
                                <name>0</name>
                                <family>
                                    <inet>
                                        <address>
                                            <name>192.168.101.101/24</name>
                                        </address>
                                    </inet>
                                </family>
                            </unit>
                        </interface>
                    </interfaces>
            </configuration>
            <cli>
                <banner>[edit]</banner>
            </cli>
        </rpc-reply>
        """
        self.assertFalse(is_vlan_used("2", command_output))
