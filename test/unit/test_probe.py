import unittest
import mock

from port_scanner.probe import *


class ProbeConnectTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_socket = mock.MagicMock(spec=socket.socket)
        self.address = ('1.1.1.1', 80)

    def connect_ex_test(self, return_value):
        self.mock_socket.connect_ex.return_value = return_value
        connect(self.mock_socket, self.address)
        self.mock_socket.connect_ex.assert_called_with(self.address)

    def test_connect(self):
        self.connect_ex_test(0)

    def test_connect_if_in_progess(self):
        self.connect_ex_test(EINPROGRESS)

    def test_connect_if_error(self):
        with self.assertRaises(socket.error):
            self.connect_ex_test(EBADF)


class ProbeTestCase(unittest.TestCase):

    @mock.patch('port_scanner.probe.create_tcp_socket')
    def setUp(self, create_tcp):
        self.mock_socket = mock.MagicMock(spec=socket.socket)
        self.mock_socket.connect_ex.return_value = EINPROGRESS
        create_tcp.return_value = self.mock_socket

        self.ip_addr = '1.1.1.1'
        self.port = 80
        self.port_probe = PortProbe(self.ip_addr, self.port)

    def test_init_result_value_unknown(self):
        self.assertEqual(self.port_probe.result, RESULT_UNKNOWN)

    def test_close(self):
        self.port_probe.close()
        self.mock_socket.close.assert_called_with()

    def test_analyze_open(self):
        self.mock_socket.getsockopt.return_value = 0

        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_OPEN)

    def test_analyze_unknown_not_connected(self):
        self.mock_socket.getsockopt.return_value = 0
        self.mock_socket.getpeername.side_effect = socket.error(ENOTCONN, 'Socket not connected yet.')

        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_UNKNOWN)

    def test_analyze_open_but_closed_by_remote(self):
        self.mock_socket.getsockopt.return_value = 0
        self.mock_socket.getpeername.side_effect = socket.error(EINVAL, 'Socket closed by remote.')

        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_OPEN)

    def test_analyze_filtered(self):
        self.mock_socket.getsockopt.return_value = ETIMEDOUT
        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_FILTERED)

    def test_analyze_closed(self):
        self.mock_socket.getsockopt.return_value = ECONNREFUSED
        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_CLOSED)

    def test_analyze_known_idempotency(self):
        self.mock_socket.getsockopt.return_value = 0

        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_OPEN)

        self.port_probe.close()

        result = self.port_probe.analyze()
        self.assertEqual(result, RESULT_OPEN)

        self.mock_socket.getsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_ERROR)


if __name__ == "__main__":
    unittest.main()
