from __future__ import absolute_import, division, print_function

from automat import MethodicalMachine


__all__ = ['ReturningPerformer', 'ServerHandshake']


# this needs an iface
class ReturningPerformer(object):

    def do(self, action):
        """
        Return the value passed in by the caller. Useful only for testing.
        """
        return action


class ServerHandshake(object):
    """
    A state-machine representing the server handshake.

    Based on the handshake protocol defined in
    :rfc:https://tools.ietf.org/html/rfc5246#section-7.3

    :param performer: The thing that should actually perform
        math/cryptography/socket manipulation.
    :type performer: an instance of `IPerformer`
    """

    _machine = MethodicalMachine()

    def __init__(self, performer):
        self._performer = performer

    # states
    @_machine.state(initial=True)
    def received_client_hello(self):
        """we've been given client hello"""

    @_machine.state()
    def sent_server_hello_done(self):
        """Server hello has been sent completely"""

    @_machine.state()
    def handshake_failed(self):
        """The handshake has failed negotiation"""

    @_machine.state()
    def change_cipher_spec_sent(self):
        """Change cipher spec message has been sent"""

    @_machine.state()
    def finished(self):
        """The server has finished negotiation"""

    # inputs
    @_machine.input()
    def client_hello(self):
        """A client hello message"""

    @_machine.input()
    def alert_message(self):
        """An alert message sent by the client"""

    # outputs
    @_machine.output()
    def _send_server_hello(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.1.3
        """
        return self._performer.do("server hello")

    @_machine.output()
    def _send_server_certificate(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.2
        """
        return self._performer.do("server certificate")

    @_machine.output()
    def _send_server_key(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.3
        """
        return self._performer.do("server key")

    @_machine.output()
    def _send_certificate_request(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.3
        """
        return self._performer.do("request client certificate")

    @_machine_output()
    def _send_server_hello_done(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.5
        """
        return self._performer.do("server hello done")

    # transitions
