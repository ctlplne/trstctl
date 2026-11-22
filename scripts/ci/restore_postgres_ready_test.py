"""The restore rehearsal must observe PostgreSQL through its published port."""

import socket
import struct
import threading
import unittest

import restore_postgres_ready


class PostgresReadyTest(unittest.TestCase):
    def test_waits_through_restart_before_accepting_stable_host_handshake(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        attempts = []

        def server():
            for response in (None, b"N", b"N"):
                conn, _ = listener.accept()
                with conn:
                    attempts.append(conn.recv(8))
                    if response is not None:
                        conn.sendall(response)
            listener.close()

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        self.assertTrue(restore_postgres_ready.wait_ready(port, timeout=3, interval=0.01))
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(attempts, [struct.pack("!II", 8, 80877103)] * 3)

    def test_rejects_open_port_that_does_not_answer_postgres(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]

        def server():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn:
                    conn.recv(8)
                    conn.sendall(b"X")

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        try:
            self.assertFalse(restore_postgres_ready.wait_ready(port, timeout=0.05, interval=0.01))
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
