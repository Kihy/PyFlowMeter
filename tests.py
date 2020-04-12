import unittest
from IncrementalStatistics import *
from py_flow_meter import *
from scipy.stats import kurtosis, skew

class Test(unittest.TestCase):

    def test_decode_flags(self):
        hex_repr1="0x10"
        hex_repr2="0x18"
        hex_repr3="0x12"

        np.testing.assert_array_equal(decode_flags("0x10"), np.array([i for i in "00010000"],dtype="int32"))
        np.testing.assert_array_equal(decode_flags("0x18"), np.array([i for i in "00011000"],dtype="int32"))
        np.testing.assert_array_equal(decode_flags("0x12"), np.array([i for i in "00010010"],dtype="int32"))


    def test_statistics(self):
        """
        tests the accuracy of online algorithm against numpy and scipy methods
        Using samples of size 10,100,1000,10000 ranging from 0 to 100 with
        epsilon value of 1e-4

        Returns:
            None

        """
        num_samples = [10, 100, 1000, 10000]
        epsilon = 1e-4
        for n in num_samples:
            samples = np.random.randint(100, size=n)
            real_mean = np.mean(samples)
            real_std = np.std(samples)
            real_skew = skew(samples)
            real_kurtosis = kurtosis(samples)
            real_min=np.min(samples)
            real_max=np.max(samples)

            # online algorithm
            inc_stat=IncStats()
            for i in range(n):
                inc_stat.update(samples[i])

            test_mean, test_std,test_skew,test_kurtosis,test_min,test_max= inc_stat.get_statistics()
            self.assertAlmostEqual(test_mean, real_mean, delta=epsilon)
            self.assertAlmostEqual(test_std, real_std,  delta=epsilon)
            self.assertAlmostEqual(test_skew, real_skew,  delta=epsilon)
            self.assertAlmostEqual(
                test_kurtosis, real_kurtosis,  delta=epsilon)
            self.assertAlmostEqual(test_min, real_min,  delta=epsilon)
            self.assertAlmostEqual(test_max, real_max,  delta=epsilon)

if __name__ == '__main__':
    unittest.main()
