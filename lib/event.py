class Event:
    def __init__(self, o, t, a):
        self._operation = o
        self._time = t
        self._args = a
        self._done = False

    def get_time(self):
        return self._time

    def get_operation(self):
        return self._operation

    def get_number_of_arguments(self):
        return len(self._args)

    def get_argument(self, i):
        return self._args[i]

    def __str__(self):
        s = "Event \'{0}\' occurring at time {1}".format(self._operation, self._time)
        if len(self._args) > 0:
            s += " with parameters {}".format(self._args)
        return s

    def set_done(self):
        self._done = True

    def get_state(self):
        return self._done
