import redis, json, requests, subprocess, datetime, pytz, math, re, os
from typing import Union
from abc import ABC, abstractmethod

#Remark: all datetimes from sufshark server are in UTC+0 timezone

################### global variables section ###################
script_location:str = "/usr/python/surfshark_wireguard_token.py"
current_timezone:datetime.timezone = pytz.timezone(os.environ['timezone'])

method:str = os.environ.get('method') if os.environ.get('method') in ['File', 'Redis'] else "File"
data_file_name:str = "/usr/python/data"

redis_hostname:str = os.environ.get('redis_host') if os.environ.get('redis_host') is not None else "redis"
redis_port:int = os.environ.get('redis_port') if os.environ.get('redis_port') is not None else 6379

username:str = os.environ["username"]
password:str = os.environ['password']
############### end of global variables section ################

class DataHandler(ABC):
    @abstractmethod
    def __init__(self):
        self.className = ""
        self.pubKey = None
        self.privateKey = None
        self.token = None
        self.renewToken = None
        self.jobId = None
        self.expiredDatetime = None
        self.scheduleDatetime = None


    @abstractmethod
    def setPubPrivateKey(self, pub_key:str, private_key:str) -> bool:
        pass

    @abstractmethod
    def getPubPrivateKey(self) -> None:
        pass


    @abstractmethod
    def setTokenAndRenewToken(self, token:str, renew_token:str) -> bool:
        pass

    @abstractmethod
    def getTokenAndRenewToken(self) -> None:
        pass


    @abstractmethod
    def setJobId(self, jobId: str) -> bool:
        pass

    @abstractmethod
    def getJobId(self) -> None:
        pass


    @abstractmethod
    def setExpirationDatetime(self, expired_datetime: str) -> bool:
        pass

    @abstractmethod
    def getExpirationDatetime(self) -> None:
        pass


    @abstractmethod
    def setScheduleDatetime(self, scheduleDatetime: str) -> bool:
        pass

    @abstractmethod
    def getScheduleDatetime(self) -> None:
        pass


class FileHandler(DataHandler):
    def __init__(self, file_name:str):
        super().__init__()
        self.file_name = file_name
        self.className = "File"

        if not os.path.exists(file_name):
            self.initializeDataJsonToFile()
        else:
            self.readDataJsonFromFile()

    
    def initializeDataJsonToFile(self) -> None:
        with open(data_file_name, "w") as f:
            initial_data_json = {
                "pubKey": None,
                "privateKey": None,
                "token": None,
                "renewToken": None,
                "jobId": None,
                "expiredDatetime": None,
                "scheduleDatetime": None
            }
            f.write(json.dumps(initial_data_json))
    
    def readDataJsonFromFile(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.pubKey = data_json["pubKey"]
            self.privateKey = data_json["privateKey"]
            self.token = data_json["token"]
            self.renewToken = data_json["renewToken"]
            self.jobId = data_json["jobId"]
            self.expiredDatetime = data_json["expiredDatetime"]
            self.scheduleDatetime = data_json["scheduleDatetime"]


    ###############  getter/setter section ############### 
    def setPubPrivateKey(self) -> bool:
        try:
            with open(self.file_name, "r+") as f:
                data_json = json.load(f)
                data_json["pubKey"] = self.pubKey
                data_json["privateKey"] = self.privateKey
                f.seek(0)
                f.write(json.dumps(data_json))
                f.truncate()

            print(f"Public and private key set to {self.className} correctly.")
            print("------------- token ---------------")
            print(f"public key: [{self.pubKey}]")
            print(f"private key: [{self.privateKey}]")
            print("-----------------------------------")
            return True
        except Exception as e:
            print(f"Public and private key set to {self.className} incorrectly.")
            return False
    
    def getPubPrivateKey(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.pubKey, self.privateKey = data_json["pubKey"], data_json["privateKey"]


    def setTokenAndRenewToken(self) -> bool:
        try:
            with open(self.file_name, "r+") as f:
                data_json = json.load(f)
                data_json["token"] = self.token
                data_json["renewToken"] = self.renewToken
                f.seek(0)
                f.write(json.dumps(data_json))
                f.truncate()
            
            print(f"Token and renew token set to {self.className} correctly.")
            return True
        except Exception as e:
            print(f"Token and renew token set to {self.className} incorrectly.")
            return False

    def getTokenAndRenewToken(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.token, self.renewToken = data_json["token"], data_json["renewToken"]


    def setJobId(self, jobId: str) -> bool:
        try:
            with open(self.file_name, "r+") as f:
                data_json = json.load(f)
                data_json["jobId"] = jobId
                f.seek(0)
                f.write(json.dumps(data_json))
                f.truncate()

            print(f"Schedule job id[{jobId}] set to {self.className} correctly.")
            return True
        except Exception as e:
            print(f"Schedule job id[{jobId}] set to {self.className} incorrectly.")
            return False

    def getJobId(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.jobId = data_json["jobId"]


    def setExpirationDatetime(self, expired_datetime: str) -> bool:
        try:
            with open(self.file_name, "r+") as f:
                data_json = json.load(f)
                data_json["expiredDatetime"] = expired_datetime
                f.seek(0)
                f.write(json.dumps(data_json))
                f.truncate()

            formated_expired_datetime = datetime.datetime.strptime(expired_datetime, '%Y-%m-%dT%H:%M:%S%z').astimezone(current_timezone).isoformat()
            print(f"Expiration datetime[{formated_expired_datetime}] set to {self.className} correctly.")
            return True
        except Exception as e:
            print(f"Expiration datetime[{expired_datetime}] set to {self.className} incorrectly.")
            return False

    def getExpirationDatetime(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.expiredDatetime = data_json["expiredDatetime"]

    
    def setScheduleDatetime(self, scheduleDatetime: str) -> bool:
        try:
            with open(self.file_name, "r+") as f:
                data_json = json.load(f)
                data_json["scheduleDatetime"] = scheduleDatetime
                f.seek(0)
                f.write(json.dumps(data_json))
                f.truncate()

            print(f"Schedule time[{scheduleDatetime}] set to {self.className} correctly.")
            return True
        except Exception as e:
            print(f"Schedule time[{scheduleDatetime}] set to {self.className} incorrectly.")
            return False
    

    def getScheduleDatetime(self) -> None:
        with open(self.file_name, "r") as f:
            data_json = json.load(f)
            self.scheduleDatetime = data_json["scheduleDatetime"]
    ############### end of getter/setter section ###############


class RedisHandler(DataHandler):
    def __init__(self):
        super().__init__()
        self.className = "Redis"
        self.r = redis.Redis(host=redis_hostname, port=redis_port, db=0, decode_responses=True)
        self.readDataJsonFromRedis()

    def readDataJsonFromRedis(self) -> None:
        data = self.r.mget(["pubKey", "privateKey", "token", "renewToken", "jobId", "expiredDatetime", "scheduleDatetime"])
        self.pubKey = data[0]
        self.privateKey = data[1]
        self.token = data[2]
        self.renewToken = data[3]
        self.jobId = data[4]
        self.expiredDatetime = data[5]
        self.scheduleDatetime = data[6]

    ###############  getter/setter section ############### 
    def setPubPrivateKey(self) -> bool:
        pipeline = self.r.pipeline()
        pipeline.set('pubKey', self.pubKey)
        pipeline.set('privateKey', self.privateKey)

        pubPrivateKeySetState = all(pipeline.execute())
        if pubPrivateKeySetState:
            print(f"Public and private key set to {self.className} correctly.")
            print("------------- token ---------------")
            print(f"public key: [{self.pubKey}]")
            print(f"private key: [{self.privateKey}]")
            print("-----------------------------------")
            return True
        else:
            print(f"Public and private key set to {self.className} incorrectly.")
            return False

    def getPubPrivateKey(self) -> None:
        self.pubKey, self.privateKey = self.r.mget('pubKey', 'privateKey')


    def setTokenAndRenewToken(self) -> bool:
        pipeline = self.r.pipeline()
        pipeline.set('token', self.token)
        pipeline.set('renewToken', self.renewToken)

        tokenRenewTokenSetState = all(pipeline.execute())
        if tokenRenewTokenSetState:
            print(f"Token and renew token set to {self.className} correctly.")
            return True
        else:
            print(f"Token and renew token set to {self.className} incorrectly.")
            return False
    
    def getTokenAndRenewToken(self) -> None:
        self.token, self.renewToken = self.r.mget('token', 'renewToken')


    def setJobId(self, jobId: str) -> bool:
        if self.r.set('jobId', jobId):
            print(f"Schedule job id[{jobId}] set to {self.className} correctly.")
            return True
        else:
            print(f"Schedule job id[{jobId}] set to {self.className} incorrectly.")
            return False

    def getJobId(self) -> None:
        self.jobId = self.r.get('jobId')


    def setExpirationDatetime(self, expired_datetime: str) -> bool:
        if self.r.set('expiredDatetime', expired_datetime):
            formated_expired_datetime = datetime.datetime.strptime(expired_datetime, '%Y-%m-%dT%H:%M:%S%z').astimezone(current_timezone).isoformat()
            print(f"Expiration datetime[{formated_expired_datetime}] set to {self.className} correctly.")
            return True
        else:
            print(f"Expiration datetime set to {self.className} incorrectly.")
            return False
    
    def getExpirationDatetime(self) -> None:
        self.expiredDatetime = self.r.get('expiredDatetime')
    

    def setScheduleDatetime(self, scheduleTime: str) -> bool:
        if self.r.set('scheduleDatetime', scheduleTime):
            print(f"Schedule time[{scheduleTime}] set to {self.className} correctly.")
            return True
        else:
            print(f"Schedule time[{scheduleTime}] set to {self.className} incorrectly.")
            return False
    
    def getScheduleDatetime(self) -> None:
        self.scheduleDatetime = self.r.get('scheduleDatetime')
    ############### end of getter/setter section ############### 
    

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

    def scheduleTokenRenewal(self, minutes: int, data_handler: DataHandler) -> None:
        previousJobId = data_handler.jobId
        if previousJobId is not None:
            self.removeScheduleJob(previousJobId)

        result = subprocess.getoutput(f"echo 'python {script_location}' | at now +{minutes} minutes")
        if result_re := re.match(r"^.+\njob (?P<jobID>\d+) at (?P<datetime>.+)\n.+$", result):
            job_id_str = result_re['jobID']
            data_handler.setJobId(job_id_str)

            #remove space induced by involving single digit of day 
            schedule_dateime_str = result_re['datetime']
            normalized_schedule_dateime_str = re.sub(r'\s+', r' ', schedule_dateime_str)
            schedule_time = datetime.datetime.strptime(normalized_schedule_dateime_str, r"%a %b %d %H:%M:%S %Y").astimezone(current_timezone)
            data_handler.setScheduleDatetime(schedule_time.isoformat())


class Utility:
    def __init__(self, method: str):
        if method == "File":
            self.data_handler = FileHandler(file_name=data_file_name)
        elif method == "Redis":
            self.data_handler = RedisHandler()
        self.surfShark = Surfshark()
        self.atLinux = ATLinux()

    def initializeTokenAndRenewToken(self) -> bool:
        if self.data_handler.token is None or self.data_handler.renewToken is None:
            # no token or renewToken in redis/file, need to login to surfshark, then get new token & renewToken
            loginStatus = self.surfShark.loginSurfshark(username, password)
            if not loginStatus:
                return
            self.data_handler.token, self.data_handler.renewToken = loginStatus
            print(f"Set token & renew token to {self.data_handler.className} {'correctly' if self.data_handler.setTokenAndRenewToken() else 'incorrectly'}.")
        else:
            self.data_handler.getTokenAndRenewToken()
    
    def initializePubKeyAndPrivateKey(self) -> bool:
        if self.data_handler.pubKey is None or self.data_handler.privateKey is None:
            self.data_handler.pubKey, self.data_handler.privateKey = self.surfShark.generatePubPrivateKeys()
            print(f"Set pubKey & privateKey to {self.data_handler.className} {'correctly' if self.data_handler.setPubPrivateKey() else 'incorrectly'}")
        else:
            self.data_handler.getPubPrivateKey()

    def registerOrRenewTokenWithPubKey(self) -> bool:
        regPubKeyState = self.surfShark.regPubKey(self.data_handler.pubKey, self.data_handler.token)
        if (regPubKeyState == 409 and not self.surfShark.validateToken(self.data_handler.pubKey, self.data_handler.token)) or (regPubKeyState not in [201, 409]):
            renewStatus = self.surfShark.tokenRenewal(self.data_handler.pubKey, self.data_handler.renewToken)
            if not renewStatus:
                return

            self.data_handler.token, self.data_handler.renewToken = renewStatus
            self.data_handler.setTokenAndRenewToken()

            #save the expiration time of token
            self.surfShark.validateToken(self.data_handler.pubKey, self.data_handler.token)
    
    def scheduleTokenRenewal(self) -> None:
        if self.surfShark.expired_datetime != None:
            expired_datetime = datetime.datetime.strptime(self.surfShark.expired_datetime, r"%Y-%m-%dT%H:%M:%S%z").astimezone(current_timezone)
            self.data_handler.setExpirationDatetime(expired_datetime.isoformat())

            current_datetime = datetime.datetime.now().astimezone(current_timezone)
            diff = expired_datetime - current_datetime
            
            #TODO: need to handle the case when the token is expired

            diff_minutes = math.floor(diff.total_seconds() / 60)
            target_minutes = diff_minutes - 30

            self.atLinux.scheduleTokenRenewal(target_minutes, self.data_handler)

    def run(self):
        self.initializeTokenAndRenewToken()
        self.initializePubKeyAndPrivateKey()
        self.registerOrRenewTokenWithPubKey()
        self.scheduleTokenRenewal()

def main():
    Utility(method=method).run()

if __name__ == '__main__':
    main()