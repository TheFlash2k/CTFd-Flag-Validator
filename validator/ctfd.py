from .logger import logger
import requests
from typing import List, Dict
import os

class CTFd:

    class RequestHandler:

        GET = requests.get
        POST = requests.post
        PUT = requests.put
        DELETE = requests.delete
        PATCH = requests.patch

        def MakeRequest(mode, url: str, token, headers: dict = {}, **kwargs):

            if token == None:
                raise Exception("Token is not set. Required for requests.")

            headers["Authorization"] = f"Token {token}"
            headers["Content-Type"] = "application/json"
            headers["User-Agent"] = "CTFd-CLI-v0.1" # Cuz why not..

            try:
                return mode(url, headers=headers, **kwargs)
            except Exception as E:
                logger.error(f"An error occurred when making a request to {url}: {E.__str__()}")

    def __init__(self):
        self.instance = os.getenv("CTFD_INSTANCE", "")
        self.token = os.getenv("CTFD_ADMIN_TOKEN", "")

        if not self.instance:
            raise Exception("CTFD_INSTANCE is not set")
        
        if not self.token:
            raise Exception("CTFD_ADMIN_TOKEN is not set")
        
        logger.info("Initialized CTFd instance handler")

    def get_flags(self):
        logger.info("Getting flags...")
        r = CTFd.RequestHandler.MakeRequest(
            mode=CTFd.RequestHandler.GET,
            url=f"{self.instance}/api/v1/flags",
            token=self.token
        )

        if r.status_code != 200:
            logger.error(f"An error occurred when getting flags: {r.json()}")
            return []

        return r.json()['data']
    
    def get_regex_flags(self):
        logger.info("Getting regex flags...")
        r = CTFd.RequestHandler.MakeRequest(
            mode=CTFd.RequestHandler.GET,
            url=f"{self.instance}/api/v1/flags",
            token=self.token,
            params={"type": "regex"}
        )

        if r.status_code != 200:
            logger.error(f"An error occurred when getting regex flags: {r.json()}")
            return []

        return r.json()['data']
    
    def get_challenge_name(self, chal_id) -> str:
        logger.info("Getting challenge name...")
        r = CTFd.RequestHandler.MakeRequest(
            mode=CTFd.RequestHandler.GET,
            url=f"{self.instance}/api/v1/challenges/{chal_id}",
            token=self.token
        )

        if r.status_code != 200:
            logger.error(f"An error occurred when getting challenge name: {r.json()}")
            return None

        return r.json()['data']['name']

    def get_challenge_flag(self, chal_id):
        logger.info("Getting challenge flags...")
        r = CTFd.RequestHandler.MakeRequest(
            mode=CTFd.RequestHandler.GET,
            url=f"{self.instance}/api/v1/flags",
            token=self.token,
            params={"type": "regex", "challenge_id": chal_id}
        )

        if r.status_code != 200:
            logger.error(f"An error occurred when getting challenge flags: {r.json()}")
            return []

        return r.json()['data']

    def get_submitted_flags(self, chal_id) -> List[Dict]:
        logger.info(f"Getting submitted flags for challenge {chal_id}...")
        r = CTFd.RequestHandler.MakeRequest(
            mode=CTFd.RequestHandler.GET,
            url=f"{self.instance}/api/v1/submissions",
            token=self.token,
            params={"challenge_id": chal_id, "type": "correct"}
        )

        if r.status_code != 200:    
            logger.error(f"An error occurred when getting submitted flags: {r.json()}")
            return []
        
        details = []
        data = r.json()['data']

        if data != []:
            for i in data:
                c_data = {
                    i['provided'] : [{
                        "user": i['user'],
                        "team": i['team'],
                        "submission_id" : i['id']
                    }]
                }
                added = False
                for detail in details:
                    if list(detail.keys())[0] == i['provided']:
                        detail[i['provided']].append({
                            "user": i['user'],
                            "team": i['team'],
                            "submission_id" : i['id']
                        })
                        added = True
                        break

                if not added:
                    details.append(c_data)

        return details
    
    def is_team(self, team_id: str) -> bool:
        url = f"{self.instance}/api/v1/teams/{team_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.GET, url, self.token).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when checking if team {team_id} exists: {E}")
            return False
        
    def is_chal(self, chal_id: str) -> bool:
        url = f"{self.instance}/api/v1/challenges/{chal_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.GET, url, self.token).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when checking if challenge {chal_id} exists: {E}")
            return False
        
    def ban_user(self, user_id: str) -> bool:
        url = f"{self.instance}/api/v1/users/{user_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.PATCH, url, self.token, json={"banned": True}).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when banning user {user_id}: {E}")
            return False
        
    def ban_team(self, team_id: str) -> bool:
        url = f"{self.instance}/api/v1/teams/{team_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.PATCH, url, self.token, json={"banned": True, "fields": []}).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when banning team {team_id}: {E}")
            return False
        
    def delete_submission(self, submission_id: str) -> bool:
        logger.info(f"Deleting submission {submission_id}...")
        url = f"{self.instance}/api/v1/submissions/{submission_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.DELETE, url, self.token).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when deleting submission {submission_id}: {E}")
            return False

    def get_team_name(self, team_id: str) -> str:
        url = f"{self.instance}/api/v1/teams/{team_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.GET, url, self.token).json()['data']['name']
        except Exception as E:
            logger.error(f"An error occurred when getting team name for team {team_id}: {E}")
            return None
        
    def get_user_name(self, user_id: str) -> str:
        url = f"{self.instance}/api/v1/users/{user_id}"
        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.GET, url, self.token).json()['data']['name']
        except Exception as E:
            logger.error(f"An error occurred when getting user name for user {user_id}: {E}")
            return None

    def send_notification(self, title: str, content: str, team_id: str = None, user_id: str = None):
        url = f"{self.instance}/api/v1/notifications"
        data = {"title": title, "content": content}
        if team_id:
            data['team_id'] = team_id
        if user_id:
            data['user_id'] = user_id

        if not team_id and not user_id:
            logger.info("Sending notification to all teams and users...")

        try:
            return self.RequestHandler.MakeRequest(self.RequestHandler.POST, url, self.token, json=data).status_code == 200
        except Exception as E:
            logger.error(f"An error occurred when sending notification: {E}")
            return False
        
    def send_notification_to_team(self, title: str, content: str, team_id: str):
        logger.info(f"Sending notification to team {team_id}")
        return self.send_notification(title, content, team_id=team_id)
    
    def send_notification_to_user(self, title: str, content: str, user_id: str):
        logger.info(f"Sending notification to user {user_id}")
        return self.send_notification(title, content, user_id=user_id)
