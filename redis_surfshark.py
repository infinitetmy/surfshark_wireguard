import redis, requests, subprocess, datetime, pytz, math, re, os
from typing import Union

#Remark: all datetimes from sufshark server are in UTC+0 timezone

################### global variables section ###################
script_location:str = "/usr/python/redis_surfshark.py"
current_timezone:datetime.timezone = pytz.timezone(os.environ['timezone'])

redis_hostname:str = "redis"
redis_port:int = 6379

username:str = os.environ["username"]
password:str = os.environ['password']
############### end of global variables section ################


class Redis:
    def __init__(self):
        self.r = redis.Redis(host=redis_hostname, port=redis_port, db=0, decode_responses=True)
        self.pubKey = None
        self.privateKey = None
        self.token = None
        self.renewToken = None

    def setPubPrivateKeyToRedis(self) -> bool:
        pipeline = self.r.pipeline()
        pipeline.set('pubKey', self.pubKey)
        pipeline.set('privateKey', self.privateKey)

        pubPrivateKeySetState = all(pipeline.execute())
        if pubPrivateKeySetState:
            print("Public and private key set to redis correctly.")
            print("------------- token ---------------")
            print(f"public key: [{self.pubKey}]")
            print(f"private key: [{self.privateKey}]")
            print("-----------------------------------")
            return True
        else:
            print("Public and private key set to redis incorrectly.")
            return False

    def setTokenAndRenewTokenToRedis(self) -> bool:
        pipeline = self.r.pipeline()
        pipeline.set('token', self.token)
        pipeline.set('renewToken', self.renewToken)

        tokenRenewTokenSetState = all(pipeline.execute())
        if tokenRenewTokenSetState:
            print("Token and renew token set to redis correctly.")
            return True
        else:
            print("Token and renew token set to redis incorrectly.")
            return False

    def setExpirationDateToRedis(self, expired_datetime: str) -> bool:
        if self.r.set('expiredDatetime', expired_datetime):
            formated_expired_datetime = datetime.datetime.strptime(expired_datetime, '%Y-%m-%dT%H:%M:%S%z').astimezone(current_timezone).isoformat()
            print(f"Expiration datetime[{formated_expired_datetime}] set to redis correctly.")
            return True
        else:
            print("Expiration datetime set to redis incorrectly.")
            return False

    def setJobIdToRedis(self, jobId: str) -> bool:
        if self.r.set('jobId', jobId):
            print(f"Schedule job id[{jobId}] set to redis correctly.")
            return True
        else:
            print(f"Schedule job id[{jobId}] set to redis incorrectly.")
            return False

    def setScheduleTimeToRedis(self, scheduleTime: str) -> bool:
        if self.r.set('scheduleDatetime', scheduleTime):
            print(f"Schedule time[{scheduleTime}] set to redis correctly.")
            return True
        else:
            print(f"Schedule time[{scheduleTime}] set to redis incorrectly.")
            return False

class Surfshark:
    def __init__(self):
        self.surfsharkBasicUrl = "https://api.surfshark.com/v1"
        self.expired_datetime = None

    def generatePubPrivateKeys(self) -> tuple[str, str]:
        privateKey = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
        pubKey = subprocess.check_output(f"echo '{privateKey}' | wg pubkey", shell=True).decode('utf-8').strip()
        return pubKey, privateKey

    def loginSurfshark(self, userName: str, password: str) -> Union[tuple[str, str], bool]:
        loginUrl = f"{self.surfsharkBasicUrl}/auth/login"
        json_data = dict(username=userName, password=password)
        
        newTokenRenewTokenResponse = requests.post(loginUrl, json=json_data)
        if newTokenRenewTokenResponse.status_code == 429:
            print("Too many requests. Please try again later.")
            return False
        elif newTokenRenewTokenResponse.status_code != 200:
            print("Invalid username or password.")
            return False

        data = newTokenRenewTokenResponse.json()
        return data['token'], data['renewToken']

    def regPubKey(self, pubKey: str, token: str) -> int:
        pubKeyUrl = f'{self.surfsharkBasicUrl}/account/users/public-keys'
        headers = {'Authorization': f'Bearer {token}'}
        json_data = {'pubKey': pubKey}
        response = requests.post(pubKeyUrl, headers=headers, json=json_data)

        if response.status_code == 201:
            print("Public key registered successfully.")
            self.expired_datetime = response.json()['expiresAt']
        elif response.status_code == 401:
            print("Token is corrupted, probably public key registration is removed in Surfshark portal.")
        elif response.status_code == 409:
            print("Registered already!")
        else:
            print("Failed to register public key!")

        return response.status_code

    def validateToken(self, pubKey: str, token: str) -> bool:
        validateTokenUrl = f'{self.surfsharkBasicUrl}/account/users/public-keys/validate'
        headers = {'Authorization': f'Bearer {token}'}
        json_data = {'pubKey': pubKey}
        response = requests.post(validateTokenUrl, headers=headers, json=json_data)

        if response.status_code != 200:
            return False

        data = response.json()

        self.expired_datetime = data['expiresAt']
        return True

    def tokenRenewal(self, pubKey: str, renewToken: str) -> tuple[str, str]:
        renewTokenUrl = f'{self.surfsharkBasicUrl}/auth/renew'
        headers = {'Authorization': f'Bearer {renewToken}'}
        json_data = {'pubKey': pubKey}
        response = requests.post(renewTokenUrl, headers=headers, json=json_data)

        if response.status_code != 200:
            return None

        print("Token renewed successfully.")
        data = response.json()
        return data['token'], data['renewToken']

class ATLinux:
    def removeScheduleJob(self, jobId: str) -> bool:
        result = subprocess.getoutput(f"atrm {jobId}")
        if result == "":
            print(f"Schedule job id[{jobId}] removed from AT Linux program successfully.")
            return True
        elif result == f"Cannot find jobid {jobId}":
            print(f"Schedule job id[{jobId}] does not exist in AT Linux program.")
            return True
        else:
            print(f"Unexpected error: {result}")
            return False


    def scheduleTokenRenewal(self, minutes: int, redis: Redis) -> None:
        previousJobId = redis.r.get("jobId")
        if previousJobId is not None:
            self.removeScheduleJob(previousJobId)

        result = subprocess.getoutput(f"echo 'python {script_location}' | at now +{minutes} minutes")
        if result_re := re.match(r"^.+\njob (?P<jobID>\d+) at (?P<datetime>.+)\n.+$", result):
            job_id_str = result_re['jobID']
            redis.setJobIdToRedis(job_id_str)

            #remove space induced by involving single digit of day 
            schedule_dateime_str = result_re['datetime']
            normalized_schedule_dateime_str = re.sub(r'\s+', r' ', schedule_dateime_str)
            schedule_time = datetime.datetime.strptime(normalized_schedule_dateime_str, r"%a %b %d %H:%M:%S %Y").astimezone(current_timezone)
            redis.setScheduleTimeToRedis(schedule_time.isoformat())

class Utility:
    def __init__(self):
        self.redis = Redis()
        self.surfShark = Surfshark()
        self.atLinux = ATLinux()

    def initializeTokenAndRenewToken(self) -> bool:
        if self.redis.r.exists('token') == 0 or self.redis.r.exists('renewToken') == 0:
            # no token or renewToken in redis, need to login to surfshark, then get new token & renewToken
            loginStatus = self.surfShark.loginSurfshark(username, password)
            if not loginStatus:
                return
            self.redis.token, self.redis.renewToken = loginStatus
            print(f"Set token & renew token to redis {self.redis.setTokenAndRenewTokenToRedis() if 'correctly' else 'incorrectly'}.")
        else:
            self.redis.token, self.redis.renewToken = self.redis.r.get('token'), self.redis.r.get('renewToken')
    
    def initializePubKeyAndPrivateKey(self) -> bool:
        if self.redis.r.exists('pubKey') == 0 or self.redis.r.exists('privateKey') == 0:
            self.redis.pubKey, self.redis.privateKey = self.surfShark.generatePubPrivateKeys()
            print(f"Set pubKey & privateKey to redis {self.redis.setPubPrivateKeyToRedis() if 'correctly' else 'incorrectly'}")
        else:
            self.redis.pubKey, self.redis.privateKey = self.redis.r.get('pubKey'), self.redis.r.get('privateKey')

    def registerOrRenewTokenWithPubKey(self) -> bool:
        regPubKeyState = self.surfShark.regPubKey(self.redis.pubKey, self.redis.token)
        if (regPubKeyState == 409 and not self.surfShark.validateToken(self.redis.pubKey, self.redis.token)) or (regPubKeyState not in [201, 409]):
            renewStatus = self.surfShark.tokenRenewal(self.redis.pubKey, self.redis.renewToken)
            if not renewStatus:
                return

            self.redis.token, self.redis.renewToken = renewStatus
            self.redis.setTokenAndRenewTokenToRedis()

            #save the expiration time of token
            self.surfShark.validateToken(self.redis.pubKey, self.redis.token)
    
    def scheduleTokenRenewal(self) -> None:
        if self.surfShark.expired_datetime != None:
            expired_datetime = datetime.datetime.strptime(self.surfShark.expired_datetime, r"%Y-%m-%dT%H:%M:%S%z").astimezone(current_timezone)
            self.redis.setExpirationDateToRedis(expired_datetime.isoformat())

            current_datetime = datetime.datetime.now().astimezone(current_timezone)
            diff = expired_datetime - current_datetime
            
            #TODO: need to handle the case when the token is expired

            diff_minutes = math.floor(diff.total_seconds() / 60)
            target_minutes = diff_minutes - 30

            self.atLinux.scheduleTokenRenewal(target_minutes, self.redis)

    def run(self):
        self.initializeTokenAndRenewToken()
        self.initializePubKeyAndPrivateKey()
        self.registerOrRenewTokenWithPubKey()
        self.scheduleTokenRenewal()

def main():
    Utility().run()

if __name__ == '__main__':
    main()