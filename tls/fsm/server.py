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
    def waiting_for_client_hello(self):
        """we've been given client hello"""

    @_machine.state()
    def waiting_for_client_finished(self):
        """Waiting for client finished message"""

    @_machine.state()
    def waiting_change_cipher_spec_sent(self):
        """Change cipher spec message has been sent"""

    @_machine.state()
    def hello_finished(self):
        """The server has finished negotiation"""

    @_machine.state()
    def connection_closed(self):
        """The connection is closed"""

    # inputs
    @_machine.input()
    def hello_request(self):
        """restart the entire handshake"""

    @_machine.input()
    def basic_client_hello(self):
        """A client hello message"""

    @_machine.input()
    def client_certificate(self):
        """validate client certificate"""

    # XXX - there might need to be one of these for _every_ alert??
    @_machine.input()
    def close_notify(self):
        """close notify received"""

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

    @_machine_output()
    def _send_server_finished(self):
        """
        https://tools.ietf.org/html/rfc4346#section-7.4.9
        """
        return self._performer.do("finished")

    @_machine.output()
    def _handshake_failed(self):
        """The handshake has failed negotiation"""
        return self._performer.do("handshake_failed")

    @_machine.output()
    def _close_connection(self):
        """Tell the peer that we are shutting it down"""
        return self._performer.do("close")


    @_machine.output()
    def _change_cipher_spec(self):
        """Tell the peer to negotiate ciphers"""
        return self._performer.do("change cipherspec")

    # transitions
    # how to encode the different client hello conditions? What about client certs, etc.
    waiting_for_client_hello.upon(
        basic_client_hello,
        enter=waiting_for_client_finished,
        outputs=[_change_cipher_spec, _send_server_finished]
    )
