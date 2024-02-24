"""
Get SUSE Linux OS installed base product

.. note::
    This module parses the /etc/products.d/baseproduct and returns the base product name.
    The output is often used for reporting purposes.
"""
import io
import logging
import re
import urllib.error
import urllib.request

import salt.utils.data
import salt.utils.files
import salt.utils.path
import salt.utils.stringutils
from salt.exceptions import SaltException

log = logging.getLogger(__name__)

from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    __salt__: Any = None
    __opts__: Any = None
    __context__: Any = None
    __grains__: Any = None

def __virtual__():
    """
    Only load the module if apache is installed
    """
    if _detect_os():
        return True
    return (
        False,
        "The minion is not a SUSE Linux.",
    )

def _detect_os():
    """
    Apache commands and paths differ depending on packaging
    """
    # TODO: Add pillar support for the apachectl location
    os_family = __grains__["os_family"]
    if os_family == "Suse":
        return True
    else:
        return False

def get():
    """
    Get SUSE Linux OS installed base product name

    .. note::

        This module parses the /etc/products.d/baseproduct and returns the base product name.

    

    CLI Examples:

    .. code-block:: bash

        salt '*' baseproduct.get
    """
    baseproduct_link = "/etc/products.d/baseproduct"
    baseproduct_dir = "/etc/products.d"
    baseproduct_files = __salt__['file.find'](baseproduct_dir, name="[A-Z]*.prod")
    #print("baseproduct_files: {}".format(baseproduct_files))
    if __salt__['file.is_link'](baseproduct_link):
        product_value = __salt__['xml.get_value'](baseproduct_link, ".//shortsummary")
        return product_value
    elif len(baseproduct_files) > 0:
        product_value = __salt__['xml.get_value'](baseproduct_files[0], ".//shortsummary")
        return product_value
    else:
        return "No baseproduct file found"

    