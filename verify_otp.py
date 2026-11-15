
import json
import os
import time
import boto3
import hashlib
import hmac
import logging
import base64

from botocore.exceptions import ClientError

# ==================================================
# 1. CONFIGURATION
# ==================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = "ap-south-1"

USERS_TABLE = os.environ.get("USERS_TABLE", "DemoUsers")
OTP_TABLE = os.environ.get("OTP_TABLE", "DemoOTP")

OTP_HMAC_SECRET = os.environ.get("OTP_HMAC_SECRET", "")

MAX_ATTEMPTS = 5
LOCK_DURATION = 15 * 60

dynamodb = boto3.resource(
    "dynamodb",
    region_name=REGION
)

users_table = dynamodb.Table(USERS_TABLE)
otp_table = dynamodb.Table(OTP_TABLE)


# ==================================================
# 2. API RESPONSE HELPER
# ==================================================

def create_response(status_code, result, message):

    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps({
            "result": result,
            "message": message
        })
    }


# ==================================================
# 3. GENERATE OTP HASH
# ==================================================

def generate_otp_hash(otp):

    return hmac.new(
        OTP_HMAC_SECRET.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# ==================================================
# 4. LOCK USER ACCOUNT
# ==================================================

def lock_user_account(aadhaar_no, current_time):

    lock_time = current_time + LOCK_DURATION

    users_table.update_item(
        Key={
            "Aadharno": aadhaar_no
        },

        UpdateExpression="SET locked_until = :lock",

        ExpressionAttributeValues={
            ":lock": lock_time
        }
    )

    logger.warning("Demo account temporarily locked")


# ==================================================
# 5. MAIN LAMBDA FUNCTION
# ==================================================

def lambda_handler(event, context):

    request_id = getattr(
        context,
        "aws_request_id",
        "local"
    )

    try:

        # ------------------------------------------
        # STEP A: READ REQUEST BODY
        # ------------------------------------------

        body = event.get("body")

        if body is None:
            data = event

        elif isinstance(body, dict):
            data = body

        elif isinstance(body, str):

            if event.get("isBase64Encoded", False):
                body = base64.b64decode(body).decode("utf-8")

            try:
                data = json.loads(body)

            except json.JSONDecodeError:

                return create_response(
                    400,
                    "FAILED",
                    "Invalid JSON request body"
                )

        else:

            return create_response(
                400,
                "FAILED",
                "Invalid request body"
            )

        if not isinstance(data, dict):

            return create_response(
                400,
                "FAILED",
                "Request must be a JSON object"
            )


        # ------------------------------------------
        # STEP B: GET DEMO ID AND OTP
        # ------------------------------------------

        aadhaar_no = (
            data.get("Aadharno")
            or data.get("Aadhaarno")
        )

        otp = data.get("otp")

        if aadhaar_no is None or otp is None:

            return create_response(
                400,
                "FAILED",
                "Demo ID and OTP are required"
            )

        aadhaar_no = str(aadhaar_no).strip()
        otp = str(otp).strip()

        if len(aadhaar_no) != 12 or not aadhaar_no.isdigit():

            return create_response(
                400,
                "FAILED",
                "Invalid 12-digit demo ID"
            )

        if len(otp) != 6 or not otp.isdigit():

            return create_response(
                400,
                "FAILED",
                "Enter a valid 6-digit OTP"
            )

        if not OTP_HMAC_SECRET:

            logger.error("OTP_HMAC_SECRET is missing")

            return create_response(
                500,
                "ERROR",
                "Server configuration error"
            )


        # ------------------------------------------
        # STEP C: CHECK USER IN DEMOUSERS
        # ------------------------------------------

        user_result = users_table.get_item(
            Key={
                "Aadharno": aadhaar_no
            },
            ConsistentRead=True
        )

        user = user_result.get("Item")

        if not user:

            return create_response(
                404,
                "FAILED",
                "Demo user not found"
            )


        # ------------------------------------------
        # STEP D: CHECK ACCOUNT LOCK
        # ------------------------------------------

        current_time = int(time.time())

        locked_until = int(
            user.get("locked_until", 0)
        )

        if locked_until > current_time:

            remaining_seconds = locked_until - current_time

            return create_response(
                429,
                "FAILED",
                f"Account locked. Try again after {remaining_seconds} seconds"
            )


        # ------------------------------------------
        # STEP E: GET OTP RECORD FROM DEMOOTP
        # ------------------------------------------

        otp_result = otp_table.get_item(
            Key={
                "Aadharno": aadhaar_no
            },
            ConsistentRead=True
        )

        otp_record = otp_result.get("Item")

        logger.info("OTP record found: %s", otp_record is not None)

        if otp_record:

            logger.info(
                "Verified status: %s",
                otp_record.get("verified")
            )

            logger.info(
                "Expiry timestamp exists: %s",
                "expires_at" in otp_record
            )

            logger.info(
                "Failed attempts: %s",
                otp_record.get("failed_attempts", 0)
            )

            logger.info(
                "Current timestamp: %s",
                int(time.time())
            )

            logger.info(
                "OTP expiry timestamp: %s",
                otp_record.get("expires_at")
            )

        logger.info("User ID received: %s", aadhaar_no)

        logger.info("OTP table name: %s", OTP_TABLE)

        logger.info("OTP record found: %s", otp_record is not None)

        if not otp_record:

            return create_response(
                404,
                "FAILED",
                "OTP not found. Please request a new OTP"
            )


        # ------------------------------------------
        # STEP F: CHECK WHETHER OTP IS ALREADY USED
        # ------------------------------------------

        logger.info("Checking whether OTP is already verified")

        if otp_record.get("verified") is True:

            logger.info("OTP is already verified")

            return create_response(
                200,
                "ALREADY_VERIFIED",
                "OTP already verified. Please continue."
            )


        # ------------------------------------------
        # STEP G: CHECK OTP EXPIRY
        # ------------------------------------------

        current_time = int(time.time())

        expires_at = int(
            otp_record.get("expires_at", 0)
        )

        if expires_at <= current_time:

            return create_response(
                400,
                "FAILED",
                "OTP has expired. Please request a new OTP"
            )

        logger.info("OTP expiry check successful")


        # ------------------------------------------
        # STEP H: CHECK MAXIMUM ATTEMPTS
        # ------------------------------------------

        failed_attempts = int(
            otp_record.get("failed_attempts", 0)
        )

        if failed_attempts >= MAX_ATTEMPTS:

            lock_user_account(
                aadhaar_no,
                current_time
            )

            return create_response(
                429,
                "FAILED",
                "Maximum OTP attempts reached. Account locked for 15 minutes"
            )


        # ------------------------------------------
        # STEP I: GENERATE HASH OF ENTERED OTP
        # ------------------------------------------

        entered_otp_hash = generate_otp_hash(otp)

        stored_otp_hash = otp_record.get(
            "otp_hash",
            ""
        )

        if not stored_otp_hash:

            logger.error("OTP hash missing from DynamoDB")

            return create_response(
                500,
                "ERROR",
                "OTP verification configuration error"
            )


        # ------------------------------------------
        # STEP J: COMPARE OTP HASHES
        # ------------------------------------------

        if not hmac.compare_digest(
            entered_otp_hash,
            stored_otp_hash
        ):

            try:

                update_result = otp_table.update_item(

                    Key={
                        "Aadharno": aadhaar_no
                    },

                    UpdateExpression="ADD failed_attempts :one",

                    ConditionExpression=(
                        "verified = :false "
                        "AND expires_at > :now "
                        "AND (attribute_not_exists(failed_attempts) "
                        "OR failed_attempts < :max)"
                    ),

                    ExpressionAttributeValues={
                        ":one": 1,
                        ":false": False,
                        ":now": current_time,
                        ":max": MAX_ATTEMPTS
                    },

                    ReturnValues="ALL_NEW"
                )

                new_attempts = int(
                    update_result["Attributes"]["failed_attempts"]
                )

            except ClientError as error:

                error_code = error.response.get(
                    "Error", {}
                ).get("Code", "")

                if error_code == "ConditionalCheckFailedException":

                    latest = otp_table.get_item(
                        Key={
                            "Aadharno": aadhaar_no
                        },
                        ConsistentRead=True
                    ).get("Item", {})

                    if latest.get("verified") is True:

                        return create_response(
                            200,
                            "ALREADY_VERIFIED",
                            "OTP already verified. Please continue."
                        )

                    if int(latest.get("expires_at", 0)) <= int(time.time()):

                        return create_response(
                            400,
                            "FAILED",
                            "OTP has expired. Please request a new OTP"
                        )

                    if int(latest.get("failed_attempts", 0)) >= MAX_ATTEMPTS:

                        lock_user_account(
                            aadhaar_no,
                            int(time.time())
                        )

                        return create_response(
                            429,
                            "FAILED",
                            "Maximum OTP attempts reached. Account locked for 15 minutes"
                        )

                raise


            # Lock after fifth incorrect attempt

            if new_attempts >= MAX_ATTEMPTS:

                lock_user_account(
                    aadhaar_no,
                    current_time
                )

                return create_response(
                    429,
                    "FAILED",
                    "Maximum OTP attempts reached. Account locked for 15 minutes"
                )

            remaining = MAX_ATTEMPTS - new_attempts

            return create_response(
                400,
                "FAILED",
                f"Incorrect OTP. {remaining} attempts remaining"
            )


        # ------------------------------------------
        # STEP K: MARK OTP AS VERIFIED
        # ------------------------------------------

        try:

            otp_table.update_item(

                Key={
                    "Aadharno": aadhaar_no
                },

                UpdateExpression=(
                    "SET verified = :true, "
                    "verified_at = :now"
                ),

                ConditionExpression=(
                    "verified = :false "
                    "AND expires_at > :now"
                ),

                ExpressionAttributeValues={
                    ":true": True,
                    ":false": False,
                    ":now": int(time.time())
                }
            )

        except ClientError as error:

            error_code = error.response.get(
                "Error", {}
            ).get("Code", "")

            if error_code == "ConditionalCheckFailedException":

                latest = otp_table.get_item(
                    Key={
                        "Aadharno": aadhaar_no
                    },
                    ConsistentRead=True
                ).get("Item", {})

                if latest.get("verified") is True:

                    return create_response(
                        200,
                        "ALREADY_VERIFIED",
                        "OTP already verified. Please continue."
                    )

                return create_response(
                    400,
                    "FAILED",
                    "OTP expired. Please request a new OTP"
                )

            raise


        logger.info(
            "request_id=%s result=VERIFIED",
            request_id
        )


        # ------------------------------------------
        # STEP L: SUCCESS RESPONSE
        # ------------------------------------------

        return create_response(
            200,
            "VERIFIED",
            "OTP verified successfully"
        )


    # ----------------------------------------------
    # STEP M: HANDLE ERRORS
    # ----------------------------------------------

    except ClientError as error:

        logger.exception(
            "request_id=%s DynamoDB error",
            request_id
        )

        return create_response(
            500,
            "ERROR",
            "Database operation failed"
        )


    except Exception:

        logger.exception(
            "request_id=%s result=ERROR",
            request_id
        )

        return create_response(
            500,
            "ERROR",
            "Internal server error"
        )
