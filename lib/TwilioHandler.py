from hashlib import sha256
from random import randint

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client


class TwilioHandler:
    def __init__(self, mobile_no: str) -> None:
        """
        Constructor: Initialization script
        :param mobile_no: User mobile nos+
        """
        self.__mobile_no = mobile_no
        self.__account_sid = 'Your account id'
        self.__auth_token = 'Your auth token'
        self.__verify_sid = "Your verify id"
        self.__message_service_sid = "your message service id"
        self.__AUTO_VERIFY = False
        self.__OTP = None

        self.__client = Client(self.__account_sid, self.__auth_token)

    def auto_verify(self, try_flag: int = 1) -> bool:
        """
        Verifying User using via Twilio API
        :param try_flag: Tries for sending OTP again
        :return: Whether user verified or not
        """
        self.__AUTO_VERIFY = True
        if not self.__send_otp():
            return False
        verified = self.__verify_otp()
        if verified:
            print('verified')
            return True
        elif try_flag:
            print("Sending OTP again...")
            return self.auto_verify(try_flag - 1)
        return False

    def verify(self, try_flag: int = 1) -> bool:
        """
        Verifying user using local OTP generation
        :param try_flag: Tries for sending OTP again
        :return: Whether user verified or not
        """
        self.__AUTO_VERIFY = False
        if not self.__send_otp():
            return False
        verified = self.__verify_otp()
        if verified:
            return True
        elif try_flag:
            print("Sending another OTP!")
            return self.verify(try_flag - 1)
        return False

    def __send_otp(self) -> bool:
        """
        Sending the OTP to User Mobile no
        :return: Whether OTP sent or not
        """
        try:
            if self.__AUTO_VERIFY:
                self.__client.verify.v2.services(self.__verify_sid) \
                    .verifications \
                    .create(to=self.__mobile_no, channel="sms", locale="EN")
            else:
                self.__client.messages.create(
                    from_='+17702129883',
                    body=f'Your OTP is {self.__generate_otp()}',
                    to=self.__mobile_no
                )
        except TwilioRestException:
            print('Max OTP send limit reached... Try again after 10 minutes!')
            return False
        print(
            f"OTP sent to {TwilioHandler.__secure_mobile_no(self.__mobile_no)}")
        return True

    def __verify_otp(self) -> bool:
        """
        Taking End user OTP input and verifying it
        :return: Whether OTP verified or not
        """
        if self.__AUTO_VERIFY:
            return self.__web_verify()
        else:
            return self.__local_verify()

    def __web_verify(self, try_flag: int = 1) -> bool:
        """
        Verifying End user OTP via Twilio API
        :param try_flag: Tries for typing OTP again
        :return: Whether OTP verified or not
        """
        otp = TwilioHandler.__input_otp()
        try:
            vcheck = self.__client.verify.v2.services(self.__verify_sid) \
                .verification_checks \
                .create(to=self.__mobile_no, code=otp)
        except TwilioRestException:
            print('Max tries reached ... Try again after 10 minutes!')
            return False
        if vcheck.status == "approved":
            return True
        elif try_flag:
            print("Invalid OTP Entered, try again...")
            return self.__web_verify(try_flag - 1)
        print("Invalid OTP entered!")
        return False

    def __local_verify(self, try_flag: int = 1) -> bool:
        """
        Verifying End user via local authentication
        :param try_flag: Tries for typing OTP again
        :return: Whether OTP verified or not
        """
        otp = TwilioHandler.__input_otp()
        hashed_otp = TwilioHandler.__get_hash(otp)
        if self.__OTP == hashed_otp:
            return True
        elif try_flag:
            print("Invalid OTP entered, try again...")
            return self.__local_verify(try_flag - 1)
        print("Invalid OTP entered!")
        return False

    def __generate_otp(self) -> str:
        """
        Generating the OTP
        :return: Generated OTP
        """
        otp = ''
        for i in range(6):
            otp += str(randint(0, 9))
        self.__OTP = TwilioHandler.__get_hash(otp)
        return otp

    def send_message(self, message: str) -> None:
        """
        Sending custom messages
        """
        self.__client.messages.create(
            messaging_service_sid=self.__message_service_sid,
            body=message,
            to=self.__mobile_no
        )

    @staticmethod
    def __input_otp(msg: str = "OTP: ") -> str:
        """
        Taking End User Input OTP
        :param msg: Message for input
        :return: Input OTP
        """
        return input(msg)

    @staticmethod
    def __get_hash(data: str) -> str:
        """
        Hashing function
        :param data: Data to be hashed
        :return: SHA-256 hash
        """
        return sha256(data.encode()).hexdigest()

    @staticmethod
    def __secure_mobile_no(mobile_no: str) -> str:
        """
         Encrypting Mobile no
        :param mobile_no: User mobile no
        :return: Encrypted Mobile no
        """
        return mobile_no[:4] + "*" * (len(mobile_no) - 6) + mobile_no[-2:]
