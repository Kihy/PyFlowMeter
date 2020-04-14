import numpy as np


class IncStats():
    def __init__(self):
        """
        m (float): cumulative mean.
        m2 (float): cumulative variance.
        m3 (float): cumulative skew.
        m4 (float): cumulative kurtosis.
        n (integer): number of samples seen so far.

        Returns:
            None:

        """
        self.m = 0
        self.m2 = 0
        self.m3 = 0
        self.m4 = 0
        self.n = 0
        self.min = float("Inf")
        self.max = -float("Inf")
        self.eps = 1e-6

    def update(self, x, verbose=False):
        """
        calculates high order statistics(mean, variance, skewness and kurtosis) using
        online algorithm (so we dont get any issues with memory overflow).
        Note the returned values needs to be transformed into actual statistics.
        Args:
            x (float): the current sample value.

        Returns:
            None.

        """
        delta = x - self.m
        delta_n = delta / (self.n + 1)
        delta_n2 = delta_n**2
        term1 = delta * delta_n * self.n
        self.m = self.m + delta_n
        self.m4 = self.m4 + term1 * delta_n2 * \
            ((self.n + 1)**2 - 3 * (self.n + 1) + 3) + \
            6 * delta_n2 * self.m2 - 4 * delta_n * self.m3
        self.m3 = self.m3 + term1 * delta_n * \
            (self.n - 1) - 3 * delta_n * self.m2
        self.m2 = self.m2 + term1
        self.n += 1

        if self.min > x:
            self.min = x
        if x > self.max:
            self.max = x

    def get_statistics(self):
        """
        calculates statistics based on currently observed data.
        Note the sknew of sample with 0 is 0, and kurtosis of samples with
        same value(e.g. bunch of 1s) is -3

        Returns:
            mean, std, skewness, kurtosis, min and max:

        """

        mean = self.m
        std = np.sqrt(self.m2 / self.n)

        if self.m2 == 0:
            kurtosis = -3.
            skew = 0
        else:
            kurtosis = (self.n * self.m4) / (self.m2 * self.m2) - 3
            skew = np.sqrt(self.n) * self.m3 / self.m2**1.5
        return mean, std, skew, kurtosis, self.min, self.max
