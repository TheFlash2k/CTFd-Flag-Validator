#!/usr/bin/env python3

# *-* coding: utf-8 *-*
# *-* author: @TheFlash2k

import logging
from dotenv import load_dotenv
import os
import sys
import requests
from pprint import pprint
from typing import List, Dict
import rstr
import sqlite3
import uvicorn
from threading import Thread
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from discordwebhook import Discord as DiscordWebhook
import time


errs = {
    127 : 'Challenge ID does not exist',
    128 : 'Team ID does not exist',
    129 : 'Challenge does not have a regex-based flag'
}

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
load_dotenv()

class Discord:

    ''' Simple WebHook api to send data to a Discord channel '''
    def post(content: str, err=False):
        webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
        if not webhook:
            if err:
                raise Exception("DISCORD_WEBHOOK_URL is not set")
            else:
                logger.warning("DISCORD_WEBHOOK_URL is not set. Skipping...")
                return
        DiscordWebhook(url=webhook).post(content=content)
        logger.info(f"Posted \"{content}\" to Discord")

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

class Database:

    def __init__(self, db_name : str = "flags.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS flags (id INTEGER PRIMARY KEY, flag TEXT, team_id TEXT, chal_id TEXT)")
        self.conn.commit()

    def __del__(self):
        self.conn.close()

    def insert(self, flag: str, team_id: str, chal_id: str):
        self.cursor.execute("INSERT INTO flags (flag, team_id, chal_id) VALUES (?, ?, ?)", (flag, team_id, chal_id))
        self.conn.commit()

    def get(self, flag: str):
        self.cursor.execute("SELECT * FROM flags WHERE flag=?", (flag,))
        return self.cursor.fetchall()
    
    def get_specific(self, chal_id: str, team_id: str):
        self.cursor.execute("SELECT * FROM flags WHERE chal_id=? AND team_id=?", (chal_id, team_id))
        return self.cursor.fetchall()

    def get_all(self):
        self.cursor.execute("SELECT * FROM flags")
        return self.cursor.fetchall()
    
    def delete(self, flag: str):
        self.cursor.execute("DELETE FROM flags WHERE flag=?", (flag,))
        self.conn.commit()

    def delete_all(self):
        self.cursor.execute("DELETE FROM flags")
        self.conn.commit()

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

app = FastAPI()

@app.get("/flag", response_class=PlainTextResponse)
async def flag(team_id: str, chal_id: str):
    gen = mgr.generate_flag(chal_id, team_id)
    if type(gen) == int:
        return errs[gen]
    elif not gen:
        return "An error occurred when generating the flag. Please contact the administrator."
    return gen

@app.get("/check")
def updates():
    logger.info("Running duplicate check...")
    challs = [i['challenge_id'] for i in ctfd.get_regex_flags()]
    logger.info(f"Found {len(challs)} challenges with REGEX based flags.")
    for chal in challs:
        chal_name = ctfd.get_challenge_name(chal)
        logger.info(f"Checking challenge \"{chal_name}\"...")
        submitted = ctfd.get_submitted_flags(chal)
        msg = {'ban': [], 'msg' : [] }
        for submitted in submitted:
            vals = list(submitted.values())[0]
            flag = db.get(list(submitted.keys())[0])
            if not flag:
                logger.error(f"Flag {list(submitted.keys())[0]} does not exist in local db")
                team_id = vals[0]['team']['id']
                name = ctfd.get_team_name(team_id)
                if ctfd.ban_team(team_id):
                    logger.info(f"Successfully banned {name}")
                else:
                    logger.error(f"An error occurred when banning {name}")
                msg['ban'].append(f"**{name}** has been ***BANNED*** for submitting a flag that wasn't even generated for challenge ***{chal_name}***.")
                submission_id = vals[0]['submission_id']
                logger.info(f"Deleting submission {submission_id}...")
                if ctfd.delete_submission(submission_id):
                    logger.info(f"Successfully deleted submission {submission_id}")
                else:
                    logger.error(f"An error occurred when deleting submission {submission_id}")
                msg['msg'].append(f"Submission {submission_id} has been deleted.")
                continue

            if len(vals) != 1:
                logger.error(f"Multiple submission for flag {list(submitted.keys())[0]} found!")
                flag = db.get(list(submitted.keys())[0])
                if flag:
                    generated_by = flag[0][2]
                    generated_by_name = ctfd.get_team_name(generated_by)
                    logger.error(f"Actual flag was generated by: {generated_by}")
                    submission_ids = [i['submission_id'] for i in vals]
                    team_ids = [i['team']['id'] for i in vals]
                    if generated_by not in team_ids:
                        logger.error(f"{generated_by} did not submit the flag but it was generated by them. Banning...")
                        if ctfd.ban_team(generated_by):
                            logger.info(f"Successfully banned team {generated_by}")
                        else:
                            logger.error(f"An error occurred when banning team {generated_by}")
                        msg['ban'].append(f"**{generated_by_name}** has been ***BANNED*** for sharing flag of challenge ***{chal_name}***.")
                    other_teams = [i for i in team_ids if i != generated_by]
                    for team in other_teams:
                        logger.error(f"{team} submitted the flag but it was generated by {generated_by}. Banning...")
                        if ctfd.ban_team(team):
                            logger.info(f"Successfully banned team {team}")
                        else:
                            logger.error(f"An error occurred when banning team {team}")
                        name = ctfd.get_team_name(team)
                        if name != generated_by_name:
                               msg['ban'].append(f"**{name}** has been ***BANNED*** for submitting **{generated_by_name}**'s flag of challenge ***{chal_name}***.")
                    # Remove the submission:
                    for submission_id in submission_ids:
                        logger.info(f"Deleting submission {submission_id}...")
                        if ctfd.delete_submission(submission_id):
                            logger.info(f"Successfully deleted submission {submission_id}")
                        else:
                            logger.error(f"An error occurred when deleting submission {submission_id}")
                        msg['msg'].append(f"Submission {submission_id} has been deleted.")
                    
            else:
                team_id = vals[0]['team']['id']
                flag = list(submitted.keys())[0]
                db_flag = db.get(flag)
                if db_flag:
                    generated_by = db_flag[0][2]
                    generated_by_name = ctfd.get_team_name(generated_by)
                    if int(generated_by) != int(team_id):
                        name = ctfd.get_team_name(team_id)
                        logger.error(f"Flag {flag} was not generated by {name} but by {generated_by_name}")
                        teams = [team_id, generated_by]
                        for team in teams:
                            if ctfd.ban_team(team):
                                logger.info(f"Successfully banned {name}")
                            else:
                                logger.error(f"An error occurred when banning {name}")
                            msg['ban'].append(f"**{generated_by_name}** has been ***BANNED*** for sharing flag of challenge ***{chal_name}***.")
                            if name != generated_by_name:
                                msg['ban'].append(f"**{name}** has been ***BANNED*** for submitting **{generated_by_name}**'s flag of challenge ***{chal_name}***.")
                        msg['msg'].append(f"Flag {flag} was not generated by {name} but by {generated_by_name}")
                        # Get submission id:
                        submission_id = vals[0]['submission_id']
                        logger.info(f"Deleting submission {submission_id}...")
                        if ctfd.delete_submission(submission_id):
                            logger.info(f"Successfully deleted submission {submission_id}")
                        else:
                            logger.error(f"An error occurred when deleting submission {submission_id}")
                        msg['msg'].append(f"Submission {submission_id} has been deleted.")
        logger.info(f"Finished checking challenge {chal}")
    logger.info("Finished duplicate check.")

    for k,v in msg.items():
        msg[k] = list(set(v))

    if msg['ban'] != []:
        _snd = "\n".join([f"- {i}" for i in msg['ban']])
        ctfd.send_notification("Flag Sharing Detected", _snd + "\n\nPowered by [`TheFlash2k`](https://github.com/theflash2k)'s Flag Sharing Detector.")
    
    # Thread(target=Discord.post, args=(f"Flag Sharing Detected\n```diff\n{''.join([f'+ {i}' + chr(10) for i in msg['msg']])}```",), daemon=True).start()
    Discord.post(f"Flag Sharing Detected\n```diff\n{''.join([f'+ {i}' + chr(10) for i in msg['msg']])}```")
    return msg

def run_updates():
    while True:
        time.sleep(ver_delay * 60)
        logger.info("Running updates")
        try:
            r = requests.get(f"http://localhost:{api_port}/update")
            logger.info("++ Respsonse from update: " + r.text)
        except Exception as E:
            logger.error(f"An error occurred when running updates: {E}")

if __name__ == "__main__":

    load_dotenv()
    api_host = os.getenv("API_HOST", "0.0.0.0")
    try:
        api_port = int(os.getenv("API_PORT", 9512))
        ver_delay = int(os.getenv("VERIFICATION_DELAY", 1))
    except Exception as E:
        logger.error(f"An error occurred when parsing API_PORT or VERIFICATION_DELAY. Ensure that they're numbers..\nError: {E}")
        sys.exit(1)
    db_name = os.getenv("DB_NAME", "flags.db")

    ctfd = CTFd()
    db = Database(db_name=db_name)
    mgr = Manager(ctfd=ctfd, db=db)
    logger.info("Starting flag validator")
    th = Thread(target=run_updates, daemon=True)
    th.start()

    uvicorn.run(app, host=api_host, port=api_port)