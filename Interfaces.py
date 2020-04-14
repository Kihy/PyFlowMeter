import abc


class StreamingInterface(metaclass=abc.ABCMeta):
    """
    An interface for packet input. It acts as a observable in observer pattern,
    other than standard attach, detach, _notify function it also needs a start
    function to start capturing packet.
    """
    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def attach(self):
        pass

    @abc.abstractmethod
    def detach(self):
        pass

    @abc.abstractmethod
    def _notify(self):
        pass

    @abc.abstractmethod
    def _end_signal(self):
        pass

        
class Observer(metaclass=abc.ABCMeta):
    """
    Define an updating interface for objects that should be notified of
    changes in a subject(streaming interface).
    """

    @abc.abstractmethod
    def update(self, packet):
        pass

    @abc.abstractmethod
    def close(self):
        pass
