import pytest
import unittest
import trapd_runtime_pid
import trapd_io
 
class test_save_pid(unittest.TestCase):
    """
    Test the save_pid mod
    """
 
    def test_correct_usage(self):
        """
        Test that attempt to create pid file in standard location works
        """
        result = trapd_runtime_pid.save_pid('/tmp/snmptrap_test_pid_file')
        self.assertEqual(result, True)
 
    def test_missing_directory(self):
        """
        Test that attempt to create pid file in missing dir fails
        """
        result = trapd_runtime_pid.save_pid('/bogus/directory/for/snmptrap_test_pid_file')
        self.assertEqual(result, False)
 
class test_rm_pid(unittest.TestCase):
    """
    Test the rm_pid mod
    """
 
    def test_correct_usage(self):
        """
        Test that attempt to remove pid file in standard location works
        """
        # must create it before removing it
        result = trapd_runtime_pid.save_pid('/tmp/snmptrap_test_pid_file')
        self.assertEqual(result, True)
        result = trapd_runtime_pid.rm_pid('/tmp/snmptrap_test_pid_file')
        self.assertEqual(result, True)
 
    def test_missing_file(self):
        """
        Test that attempt to rm non-existent pid file fails
        """
        result = trapd_runtime_pid.rm_pid('/tmp/snmptrap_test_pid_file_9999')
        self.assertEqual(result, False)
 
 
if __name__ == '__main__':
    unittest.main()
