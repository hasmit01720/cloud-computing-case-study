
import json
import os
import time
import boto3
import secrets
import hashlib
import hmac
import logging

# --------------------------------------------------
# 1. CONFIGURATION
# --------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = "ap-south-1"

USERS_TABLE = os.environ.get("USERS_TABLE", "DemoUsers")
OTP_TABLE = os.environ.get("OTP_TABLE", "DemoOTP")

SMS_MODE = os.environ.get("SMS_MODE", "SIMULATE").upper()

# SES sender email: must be verified in Amazon SES
FROM_EMAIL = os.environ.get("FROM_EMAIL", "")

OTP_EXPIRY = 5 * 60
MAX_ATTEMPTS = 5

OTP_HMAC_SECRET = os.environ.get("OTP_HMAC_SECRET", "")

# AWS connections
dynamodb = boto3.resource("dynamodb", region_name=REGION)

users_table = dynamodb.Table(USERS_TABLE)
otp_table = dynamodb.Table(OTP_TABLE)

sns = boto3.client("sns", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)


# --------------------------------------------------
# 2. API RESPONSE HELPER
# --------------------------------------------------

def create_response(status_code, result, message, extra=None):

    body = {
        "result": result,
        "message": message
    }

    if extra:
        body.update(extra)

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body)
    }


# --------------------------------------------------
# 3. MASK CONTACT DETAILS
# --------------------------------------------------

def mask_mobile(mobile):
    return "XXXXXX" + mobile[-4:]


def mask_email(email):
    try:
        name, domain = email.split("@", 1)

        if len(name) <= 2:
            masked_name = name[0] + "*"
        else:
            masked_name = name[:2] + "*" * (len(name) - 2)

        return masked_name + "@" + domain

    except ValueError:
        return "Hidden"


# --------------------------------------------------
# 4. NORMALIZE MOBILE NUMBER
# --------------------------------------------------

def normalize_mobile(mobile):

    mobile = str(mobile).strip().replace(" ", "").replace("-", "")

    if len(mobile) == 10 and mobile.isdigit():
        mobile = "+91" + mobile

    elif len(mobile) == 12 and mobile.startswith("91"):
        mobile = "+" + mobile

    if (
        len(mobile) != 13
        or not mobile.startswith("+91")
        or not mobile[3:].isdigit()
        or mobile[3] not in "6789"
    ):
        raise ValueError("Invalid registered mobile number")

    return mobile


# --------------------------------------------------
# 5. GENERATE SECURE OTP HASH
# --------------------------------------------------

def generate_otp_hash(otp):

    return hmac.new(
        OTP_HMAC_SECRET.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# --------------------------------------------------
# 6. SEND EMAIL USING AMAZON SES
# --------------------------------------------------

def send_email_otp(email, otp):

    subject = "Your Demo Authentication OTP"

    message = f"""
    Hello,

    Your demo authentication OTP is: {otp}

    This OTP is valid for 5 minutes.

    For security reasons, do not share this OTP with anyone.

    If you did not request this OTP, please ignore this email.

    Regards,
    Demo Authentication System
    """

    ses.send_email(
        Source=FROM_EMAIL,

        Destination={
            "ToAddresses": [email]
        },

        Message={
            "Subject": {
                "Data": subject,
                "Charset": "UTF-8"
            },

            "Body": {
                "Text": {
                    "Data": message,
                    "Charset": "UTF-8"
                }
            }
        }
    )


# --------------------------------------------------
# 7. MAIN LAMBDA FUNCTION
# --------------------------------------------------

def lambda_handler(event, context):

    request_id = getattr(context, "aws_request_id", "local")

    try:

        # ------------------------------------------
        # STEP A: READ REQUEST
        # ------------------------------------------

        logger.info("FULL EVENT: %s", json.dumps(event))

        body = event.get("body")

        if body is None:
            data = event
        elif isinstance(body, str):
            if event.get("isBase64Encoded"):
                import base64
                body = base64.b64decode(body).decode("utf-8")

            data = json.loads(body)
        elif isinstance(body, dict):
            data = body
        else:
            return create_response(
                400, "FAILED", "Invalid request body"
            )

        logger.info("PARSED DATA: %s", json.dumps(data))

        # ------------------------------------------
        # STEP B: GET DEMO ID
        # ------------------------------------------

        aadhaar_no = (
            data.get("Aadharno")
            or data.get("Aadhaarno")
            or data.get("demo_id")
        )

        logger.info("DEMO ID RECEIVED: %s", bool(aadhaar_no))

        if aadhaar_no is None or str(aadhaar_no).strip() == "":
            return create_response(
                400, "FAILED", "Demo ID is missing"
            )

        aadhaar_no = str(aadhaar_no).strip()

        if len(aadhaar_no) != 12 or not aadhaar_no.isdigit():
            return create_response(
                400, "FAILED", "Enter a valid 12-digit demo ID"
            )
                


        # ------------------------------------------
        # STEP C: FIND USER IN DEMOUSERS
        # ------------------------------------------

        result = users_table.get_item(
            Key={
                "Aadharno": aadhaar_no
            },
            ConsistentRead=True
        )

        user = result.get("Item")

        if not user:
            return create_response(
                404, "FAILED", "Demo user not found"
            )

        # ------------------------------------------
        # STEP D: CHECK ACCOUNT LOCK
        # ------------------------------------------

        current_time = int(time.time())

        locked_until = int(user.get("locked_until", 0))

        if locked_until > current_time:
            return create_response(
                429, "FAILED", "Account temporarily locked"
            )

        # ------------------------------------------
        # STEP E: GET EMAIL AND MOBILE
        # ------------------------------------------

        email = user.get("email")
        mobile = user.get("mobilenumber")

        if not email:
            return create_response(
                500, "ERROR", "Registered email address is missing"
            )

        email = str(email).strip()

        if "@" not in email or "." not in email.split("@")[-1]:
            return create_response(
                400, "FAILED", "Registered email address is invalid"
            )

        if not mobile:
            return create_response(
                500, "ERROR", "Registered mobile number is missing"
            )

        try:
            mobile = normalize_mobile(mobile)

        except ValueError:
            return create_response(
                400, "FAILED", "Registered mobile number is invalid"
            )

        # ------------------------------------------
        # STEP F: GENERATE SIX-DIGIT OTP
        # ------------------------------------------

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = generate_otp_hash(otp)

        expires_at = current_time + OTP_EXPIRY

        # ------------------------------------------
        # STEP G: SAVE OTP DETAILS IN DEMOOTP
        # ------------------------------------------

        otp_table.put_item(
            Item={
                # IMPORTANT:
                # This must match DemoOTP's partition key.
                "Aadharno": aadhaar_no,

                "otp_hash": otp_hash,
                "expires_at": expires_at,
                "failed_attempts": 0,
                "verified": False,
                "created_at": current_time
            }
        )

        # ------------------------------------------
        # STEP H: SEND OTP TO EMAIL USING SES
        # ------------------------------------------

        send_email_otp(email, otp)

        logger.info(
            "request_id=%s result=EMAIL_OTP_SENT",
            request_id
        )

        # ------------------------------------------
        # STEP I: SEND SMS USING SNS (OPTIONAL)
        # ------------------------------------------

        if SMS_MODE == "SNS":

            sns.publish(
                PhoneNumber=mobile,
                Message=(
                    f"Your demo verification OTP is {otp}. "
                    f"It expires in 5 minutes."
                )
            )

            sms_message = "SMS sent"

        else:

            sms_message = "SMS simulated"

        # ------------------------------------------
        # STEP J: SUCCESS RESPONSE
        # ------------------------------------------

        return create_response(
            200,
            "SUCCESS",
            "OTP sent successfully to registered email",
            {
                "masked_email": mask_email(email),
                "masked_mobile": mask_mobile(mobile),
                "email_status": "SENT",
                "sms_status": sms_message,
                "expires_in_seconds": OTP_EXPIRY
            }
        )

    # ----------------------------------------------
    # STEP K: HANDLE ERRORS
    # ----------------------------------------------

    except json.JSONDecodeError:

        return create_response(
            400, "FAILED", "Invalid JSON"
        )

    except Exception:

        logger.exception(
            "request_id=%s result=ERROR",
            request_id
        )

        return create_response(
            500, "ERROR", "Internal server error"
        )
