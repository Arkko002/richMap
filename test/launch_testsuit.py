import sys
sys.path.append("/home/pbl616/PycharmProjects/richMap/richMap")

import unittest
loader = unittest.TestLoader()
start_dir = "/home/pbl616/PycharmProjects/richMap/test"
suite = loader.discover(start_dir)

runner = unittest.TextTestRunner()
runner.run(suite)
