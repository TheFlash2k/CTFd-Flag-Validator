import rstr
from .ctfd import CTFd
from .db import Database
from .logger import logger

class Manager:

    def __init__(self, ctfd : CTFd, db : Database):
        self.ctfd = ctfd
        self.db = db

    def generate_flag(self, chal_id: str, team_id: str) -> str:

        def _get_flag(regex):
            return rstr.xeger(regex)

        if not self.ctfd.is_chal(chal_id):
            logger.error(f"Challenge with ID {chal_id} does not exist")
            return 127
        
        if not self.ctfd.is_team(team_id):
            logger.error(f"Team with ID {team_id} does not exist")
            return 128
        
        flag = self.ctfd.get_challenge_flag(chal_id)
        
        if not flag:
            logger.error(f"Challenge with ID {chal_id} does not have a flag")
            return 129
        
        local_flag = self.db.get_specific(chal_id, team_id)
        if local_flag:
            logger.info(f"Flag {local_flag[0][1]} for team {team_id} for chal {chal_id} already exists in local db")
            return local_flag[0][1]

        flag = _get_flag(regex=flag[0]['content'])
        submitted = self.ctfd.get_submitted_flags(chal_id)
        submitted_flags = [list(i.keys())[0] for i in submitted]

        iter = 0
        while flag in submitted_flags:
            flag = _get_flag(regex=flag[0]['content'])

            if iter == 100:
                logger.error(f"Could not generate a unique flag for team {team_id} for chal {chal_id}...")
                flag.insert(len(flag) - 2, f"_{team_id}{chal_id}")
            iter += 1

        logger.info(f"Generated flag {flag} for team {team_id} for chal {chal_id}")

        self.db.insert(flag, team_id, chal_id)
        return flag