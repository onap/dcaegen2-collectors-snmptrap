# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.
#
"""
NOTE:  This is a placeholder for now - logger has not been externalized
from the main source.

Setup custom logger for dcae_snmptrapd that incorporates
a rotating file _handler with 10 backups of diagnostic messages
:Parameters:

:Exceptions:

:Keywords:

"""

__docformat__ = 'restructuredtext'

import logging


# # # # # # # # # # # # # # # # # # #
# fx: setup _dcae_logger custom logger
# # # # # # # # # # ## # # # # # # #
def setup_dcae_logger(_yc_snmptrapd_diag, _dcae_logger_max_bytes, _dcae_logger_num_archives):
    """
    """

    _date_fmt = '%m/%d/%Y %H:%M:%S'

    _yc_snmptrapd_diag_bak = "%s.bak" % (_yc_snmptrapd_diag)
    if os.path.isfile(_yc_snmptrapd_diag):
        os.rename(_yc_snmptrapd_diag, _yc_snmptrapd_diag_bak)

    _handler = logging._handlers.RotatingFileHandler(_yc_snmptrapd_diag,
                                                     maxBytes=_dcae_logger_max_bytes,
                                                     backupCount=_dcae_logger_num_archives)

    # set logLevel - valid values NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL
    _handler.setLevel(logging.DEBUG)
    _dcae_logger.setLevel(logging.DEBUG)

    log_fmt = '%(levelname)s|%(asctime)s|%(name)s|%(process)d|%(funcName)s|'\
              '%(message)s'
    _formatter = logging.Formatter(log_fmt)
    _handler.setFormatter(formatter)
    _dcae_logger.addHandler(_handler)

    if os.path.isfile(_yc_snmptrapd_diag):
        os.chmod(_yc_snmptrapd_diag, 0o640)

    if os.path.isfile(_yc_snmptrapd_diag_bak):
        os.chmod(_yc_snmptrapd_diag_bak, 0o640)

    return _dcae_logger
