# CTFd-Flag-Validator
A Simple CTFd Plugin (not really a plugin) that will act as a flag generator and validator

> **NOTE**: This only works with challenges that have a RegEx-based Flag and works only on TEAM Mode (along with the [**containers**](https://github.com/theflash2k/containers) plugin)

The working of this is as follows:

- Creating an API using FastAPI and exposes two endpoints:
  - `/flag` - This API takes two query parameters:
    - `team_id`
    - `chal_id`
          
    And generates a FLAG based on these parameters.
  - `/check`
    - Runs a check against the submitted flags and those in the database to check for duplicates.
    - Also checks if someone without generating a flag, submitted it.
> Each team will have a single flag for a single challenge and that flag will be stored locally in `flags.db` file.

---

## Covered Scenarios

- [x] Team-A generates a flag, Team-B submits it before Team-A `(Both teams will be banned)`
- [x] Team-B generated a flag, Team-A submits it, Team-B doesn't submit `(Both teams will be banned) [Each team will have 1 flag generated per challenge, and that won't change no matter how many new instances are spawned]`
- [x] Team-A somehow guesses the Regex and generates a flag and submits it `(Team-A will be banned for brute-forcing and not solving as intended)`
- [x] Team-A and Team-B banned for using Team-A's flag. Team-C submit's Team-A's flag `(Team-C will be banned)`

---

## Environment Variables

- `CTFD_ADMIN_TOKEN`    - The CTFd API Administrator Token
- `CTFD_INSTANCE`       - The URL for the CTFd Instance
- `DISCORD_WEBHOOK_URL` - **[OPTIONAL]** - The Webhook URL to post your Ban notifications on Discord (by default, Notifications are posted on CTFd as well.)
- `API_HOST`            - **[DEFAULT: *0.0.0.0*]** - The host on which the API will listen on
- `API_PORT`            - **[DEFAULT: *9125*]** - The port on which API will listen on
- `VERIFICATION_DELAY`  - **[DEFAULT: *1*]** - The delay (in minutes), after which request to `/check` will be made.
- `DB_NAME`             - **[DEFAULT: *flags.db*]** - The local database name in which flags and their detail will be stored

---

## Integration with CTFd docker-compose:

In order to integrate this with your CTFd `docker-compose`, just copy the following config into your CTFd's docker-compose:

```yaml
  flagvalidator:
    build: . # Change this to the folder you have the source code + Dockerfile in.
    ports:
      - "172.17.0.1:9512:9512"
    environment:
      - CTFD_ADMIN_TOKEN=
      - CTFD_INSTANCE=
      - DISCORD_WEBHOOK_URL=""
      - API_HOST="0.0.0.0"
      - API_PORT=9512
      - VERIFICATION_DELAY=1
      - DB_NAME="flags.db"
    volumes:
      - .:/app/
    restart: always
```

> Make sure that you paste this under the `services` key inside the `docker-compose.yml`.

---

## Setting up the plugin

In order to set this up, we need to run this inside docker. Both Dockerfile and docker-compose.yml have been provided to make it easier. The `flags.db` will be generated at run time and the current folder will be mounted inside the docker container.

> NOTE: If you're running a local `CTFd` deployment, make sure to modify the variables inside your docker-entrypoint scripts accordingly.

---

## Setting up a challenge:

Let's suppose we have a challenge called `test_chal`, and we want to add a dynamic flag. The YAML config file is:

```yaml
name: "test_chal"
author: "TheFlash2k"
category: Test
description: Some Descriptive Description
value: 100
type: container

extra:
    initial: 100
    decay: 1
    minimum: 100
    image: test_chal:latest
    port: 8000
    command: ""
    volumes: ""
build: ./src/
flags:
    - {
        type: "regex",
        content: "CY243L{s4mpl3_fl4g_r3geX_[0-9a-zA-Z]{9}[1-9a-zA-Z]{9}[5-9a-eR-Z]{8}",
        data: "case_insensitive",
    }
state: visible
version: "0.1"
```

Now, inside the `src/` folder, a Dockerfile can be as follows:

```Dockerfile
FROM php:7.0-apache

ENV BASE_DIR="/var/www/html"
COPY ./src/ $BASE_DIR/
COPY ./docker-entrypoint.sh /
RUN echo "ServerName localhost" >> "/etc/apache2/apache2.conf"
ENTRYPOINT [ "/docker-entrypoint.sh" ]
```

Now, inside the `docker-entrypoint.sh`, we need to fetch the flag from `http://172.17.0.1:9152` (or whatever your API_PORT is)
> NOTE: The IP is of `docker0` interface on your system

> Quick Fact: Using the `containers` plugin which I've forked, I set `CHALLENGE_ID` and `TEAM_ID` as environment variable on each container being deployed, therefore, the script uses these:

```bash
service=http://172.17.0.1:9512
flag=$(curl -s $service/flag\?chal_id\=$CHALLENGE_ID\&team_id\=$TEAM_ID)
# We now have the flag in $flag and can do whatever we want:
echo $flag > /var/www/html/flag.txt
```

Similarly, for your own containers, you will have to write a similar `docker-entrypoint.sh` and set that as your entrypoint to cater for dynamic flaging. The rest will be managed by this plugin.

## Screenshots

- On the CTFd Web Page
![image](https://github.com/TheFlash2k/CTFd-Flag-Validator/assets/19727349/76e8d3f5-9fb2-4971-a082-fab1f71bb320)

- Logs being generated
![image](https://github.com/TheFlash2k/CTFd-Flag-Validator/assets/19727349/cac17bee-e843-44e8-9857-9360b34bb103)

