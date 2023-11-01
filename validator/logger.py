import logging
import sys

class Logger(object):
    class Formatter(logging.Formatter):
            
            """Logging Formatter to add colors and count warning / errors"""
            grey = "\x1b[38;20m"
            yellow = "\x1b[33;20m"
            red = "\x1b[31;20m"
            green = "\x1b[32;20m"
            bold_red = "\x1b[31;1m"
            reset = "\x1b[0m"
            format = "%(asctime)s %(levelname)s %(message)s"

            FORMATS = {
                logging.DEBUG: grey + format + reset,
                logging.INFO: green + format + reset,
                logging.WARNING: yellow + format + reset,
                logging.ERROR: red + format + reset,
                logging.CRITICAL: bold_red + format + reset
            }
    
            def format(self, record : logging.LogRecord) -> str:

                """Format the log record.
                Args:
                    record: Log record to be formatted
                
                Returns:
                    Formatted log record
                """
                log_fmt = self.FORMATS.get(record.levelno)
                formatter = logging.Formatter(log_fmt)
                return formatter.format(record)
    
    @staticmethod
    def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
        """Returns a logger object.
        Args:
            name: Name of the logger
            level: Level of the logger
        Returns:
            A logger object.
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = Logger.Formatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

logger = Logger.get_logger(__name__, level=logging.DEBUG)