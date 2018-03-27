import pytest
import unittest
import snmptrap.mod.trapd_exit as trapd_exit

pid_file="/tmp/test_pid_file"
pid_file_dne="/tmp/test_pid_file_NOT"
 
class test_cleanup_and_exit(unittest.TestCase):
    """
    Test the cleanup_and_exit mod
    """
 
    def test_normal_exit(self):
        """
        Test normal exit works as expected
        """
        open(pid_file, 'w')
    
        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = trapd_exit.cleanup_and_exit(0,pid_file)
            assert pytest_wrapped_sys_exit.type == SystemExit
            assert pytest_wrapped_sys_exit.value.code == 0

        # compare = str(result).startswith("SystemExit: 0")
        # self.assertEqual(compare, True)
 
    def test_abnormal_exit(self):
        """
        Test exit with missing PID file exits non-zero
        """
        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = trapd_exit.cleanup_and_exit(0,pid_file_dne)
            assert pytest_wrapped_sys_exit.type == SystemExit
            assert pytest_wrapped_sys_exit.value.code == 1

if __name__ == '__main__':
    unittest.main()
