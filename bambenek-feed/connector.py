""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import _check_health, operations

logger = get_logger('bambenek-feed')


class Bambenek(Connector):
    def execute(self, config, operation_name, params, **kwargs):
        try:
            op = operations.get(operation_name)
            result = op(config, params)
            return result
        except Exception as e:
            logger.exception("An exception occurred {}".format(e))
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            logger.exception("An exception occurred in check_health {}".format(e))
            raise ConnectorError(e)
