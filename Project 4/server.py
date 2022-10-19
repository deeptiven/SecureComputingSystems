""" Secure shared service """
import os
import time
from base64 import b64decode, b64encode

import jwt
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, jsonify, request
from flask_restful import Api, Resource

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

session = {}
grant_dict = {}
doc_metadata = {}

# Padding to add to strings to convert to AES block size.
PADDING = "*"


class welcome(Resource):
    """ Class to post welcome message """

    def get(self):
        """ Return a welcome message """

        return "Welcome to the secure shared server!"


class login(Resource):
    """ Class for login functionality """

    def post(self):
        """ Handle login requests """
        data = request.get_json()
        # Implement login functionality
        user_id = data["user_id"]
        statement = str(data["statement"])
        signed_statement = data["signed_statement"]
        public_key_file = "userpublickeys/" + user_id + ".pub"

        # """
        # Verify the signed statement.
        # Response format for success and failure are given below. The same
        # keys ('status', 'message', 'session_token') should be used.
        # """

        # Verify signed content.
        digest = SHA256.new(statement)

        with open(public_key_file, "r") as f_log:
            user_public_key = RSA.importKey(f_log.read())

        verifier = PKCS1_v1_5.new(user_public_key)
        success = verifier.verify(digest, b64decode(signed_statement))

        if success:
            with open("../certs/secure-shared-store.key", "r") as f_log:
                server_private_key = f_log.read()

            # Generate session token.
            # Save session token so that users can continue where they left off if server crashes.
            session_token = jwt.encode(data, server_private_key, algorithm="RS256")

            # Invalidate previous session if it exists.
            print "Invalidating existing session for " + str(user_id) + ", if any"

            for token, values in session.items():
                u_id, _ = values
                if u_id == user_id:
                    session[token] = (user_id, True)
                    with open("sessions.log", "a") as sessions_wal:
                        sessions_wal.write(str(token) + "," + str(user_id) + "," + str(True) + "\n")

                    break

            # Save session state.
            with open("sessions.log", "a") as sessions_wal:
                str_to_write = (
                    str(session_token) + "," + str(user_id) + "," + str(False) + "\n"
                )
                sessions_wal.write(str_to_write)

            session[session_token] = (user_id, False)

            # Similar response format given below can be used for all the other functions
            response = {
                "status": 200,
                "message": "Login Successful",
                "session_token": session_token,
            }
        else:
            response = {"status": 700, "message": "Login Failed"}

        return jsonify(response)


class checkout(Resource):
    """ Class for checkout functionality """

    @staticmethod
    def decrypt_key(key, cert_path="../certs/secure-shared-store.key"):
        """ Decrypt key using the server's private key """

        with open(cert_path, "rb") as f_log:
            private_key = RSA.import_key(f_log.read())

        cipher = Cipher_PKCS1_v1_5.new(private_key)

        # print(key)

        return cipher.decrypt(key, None)

    @staticmethod
    def decode_aes(cipher, string_to_decrypt):
        """ Decode string after decrypting with AES encryption """

        return cipher.decrypt(b64decode(string_to_decrypt)).rstrip(PADDING)

    def post(self):
        """
            Expected response status codes
            1) 200 - Document Successfully checked out
            2) 702 - Access denied to check out
            3) 703 - Check out failed due to broken integrity
            4) 704 - Check out failed since file not found on the server
            5) 700 - Other failures
        """
        data = request.get_json()
        # Implement checkout functionality
        if data["token"] not in session or session[data["token"]][1]:
            response = {
                "status": 700,
                "message": "Invalid session token in request",
            }

            return jsonify(response)

        did = data["did"]
        path_prefix = "documents/"

        # Check if doc exists in metadata:
        if did not in doc_metadata:
            response = {
                "status": 704,
                "message": "Check out failed since file not found on the server",
            }

            return jsonify(response)

        user_id = session[data["token"]][0]

        # Check if user has permission to checkout
        if user_id != doc_metadata[did]["owner"]:
            if did not in grant_dict:
                response = {
                    "status": 702,
                    "message": "Access denied to check out",
                }

                return jsonify(response)

            has_grant = (
                grant_dict[did]["target_UID"] == user_id
                or grant_dict[did]["target_UID"] == "0"
            )
            # is_grant_expired = True
            # has_checkout_access = False

            if has_grant:
                is_grant_expired = (
                    int(time.time()) - grant_dict[did]["grant_timestamp"]
                ) > int(grant_dict[did]["duration"])

                if is_grant_expired and not grant_dict[did]["is_expired"]:
                    grant_dict[did]["is_expired"] = True

                    with open("grant.log", "a") as grant_wal:
                        to_write = [did]
                        to_write.append(grant_dict[did]["target_UID"])
                        to_write.append(grant_dict[did]["access_type"])
                        to_write.append(grant_dict[did]["duration"])
                        to_write.append(str(grant_dict[did]["grant_timestamp"]))
                        to_write.append(str(grant_dict[did]["is_expired"]))

                        # print(",".join(to_write))
                        str_to_write = ",".join(to_write) + "\n"

                        grant_wal.write(str_to_write)

                has_checkout_access = grant_dict[did]["access_type"] in {
                    "2",
                    "3",
                }  # 2-> checkout, 3 -> both checkin and checkout

            if not has_grant or is_grant_expired or not has_checkout_access:
                response = {
                    "status": 702,
                    "message": "Access denied to check out",
                }

                return jsonify(response)

        # doc_metadata[did] = { "owner": str(user_id), "sec_flag": security_flag,
        # "key": b64encode(encrypted_key), "is_deleted": False }
        security_flag = doc_metadata[str(did)]["sec_flag"]

        with open(path_prefix + did, "rb") as f_log:
            contents = f_log.read()

        if security_flag == "1":
            key = b64decode(checkout.decrypt_key(b64decode(doc_metadata[did]["key"])))

            # Decrypt contents using AES - same key as IV
            cipher = AES.new(key, AES.MODE_CFB, key)
            decrypted_contents = checkout.decode_aes(cipher, contents)

            contents = b64encode(decrypted_contents)

        if security_flag == "2":
            # Verify signed content.
            digest = SHA256.new(contents)

            with open(path_prefix + did + "_signed", "rb") as f_log:
                signed_statement = f_log.read()

            with open("../certs/secure-shared-store.pub", "rb") as f_log:
                server_public_key = RSA.importKey(f_log.read())

            verifier = PKCS1_v1_5.new(server_public_key)
            success = verifier.verify(digest, b64decode(signed_statement))

            if success:
                contents = b64encode(contents)
            else:
                response = {
                    "status": 703,
                    "message": "Check out failed due to broken integrity",
                }

                return jsonify(response)

        response = {
            "status": 200,
            "message": "Document Successfully checked out",
            "contents": contents,
        }

        return jsonify(response)


class checkin(Resource):
    """ Class with checking functionality """

    @staticmethod
    def pad_string(string_to_pad):
        """ Pad string to convert to AES block size """

        return (
            string_to_pad
            + (AES.block_size - len(string_to_pad) % AES.block_size) * PADDING
        )

    @staticmethod
    def encode_aes(cipher, string_to_encrypt):
        """ Encode string after encrypting with AES encryption"""

        return b64encode(cipher.encrypt(checkin.pad_string(string_to_encrypt)))

    @staticmethod
    def encrypt_key(key, cert_path="../certs/secure-shared-store.pub"):
        """ Encrypt key using the server's public key """

        with open(cert_path, "rb") as f_log:
            public_key = RSA.import_key(f_log.read())

        cipher = Cipher_PKCS1_v1_5.new(public_key)

        # print(key)

        return cipher.encrypt(key)

    @staticmethod
    def sign_document(message, cert_path="../certs/secure-shared-store.key"):
        """ Sign to document to store the signed copy """

        digest = SHA256.new(message)

        # Read private key from file
        with open(cert_path, "rb") as f_log:
            private_key = RSA.importKey(f_log.read())

        # Load private key and sign message
        signer = PKCS1_v1_5.new(private_key)
        sig = signer.sign(digest)

        return sig

    def post(self):
        """
        Expected response status codes:
        1) 200 - Document Successfully checked in
        2) 702 - Access denied to check in
        3) 700 - Other failures
        """
        data = request.get_json()

        # Implement checkin functionality
        path_prefix = "documents/"

        did = data["did"]
        security_flag = data["security_flag"]
        contents = b64decode(data["contents"])

        if data["token"] not in session or session[data["token"]][1]:
            response = {
                "status": 700,
                "message": "Invalid session token in request",
            }

            return jsonify(response)

        user_id = session[data["token"]][0]

        # Check if this user has permission to update the doc
        if (did in doc_metadata and not doc_metadata[did]["is_deleted"] and user_id != doc_metadata[did]["owner"]):
            if did not in grant_dict:
                response = {
                    "status": 702,
                    "message": "Access denied to check in",
                }

                return jsonify(response)

            has_grant = (
                grant_dict[did]["target_UID"] == user_id
                or grant_dict[did]["target_UID"] == "0"
            )

            if has_grant:
                is_grant_expired = (
                    int(time.time()) - grant_dict[did]["grant_timestamp"]
                ) > int(grant_dict[did]["duration"])

                if is_grant_expired and not grant_dict[did]["is_expired"]:
                    grant_dict[did]["is_expired"] = True

                    with open("grant.log", "a") as grant_wal:
                        to_write = [did]
                        to_write.append(grant_dict[did]["target_UID"])
                        to_write.append(grant_dict[did]["access_type"])
                        to_write.append(grant_dict[did]["duration"])
                        to_write.append(str(grant_dict[did]["grant_timestamp"]))
                        to_write.append(str(grant_dict[did]["is_expired"]))

                        str_to_write = ",".join(to_write) + "\n"
                        grant_wal.write(str_to_write)

                has_checkin_access = grant_dict[did]["access_type"] in {
                    "1",
                    "3",
                }  # 1-> checkin, 3 -> both checkin and checkout

            if not has_grant or is_grant_expired or not has_checkin_access:
                response = {
                    "status": 702,
                    "message": "Access denied to check in",
                }

                return jsonify(response)

            # User has permission, replace user_id with owner for simpler implementation
            user_id = doc_metadata[did]["owner"]

        # Handle security flag: 1 -> Confidentiality; 2 -> Integrity

        # 1 -> Confidentiality
        if str(security_flag) == "1":
            key = AES.get_random_bytes(AES.block_size)

            # Encrypt key with server's public key
            encrypted_key = checkin.encrypt_key(b64encode(key))

            # Encrypt contents using AES
            cipher = AES.new(key, AES.MODE_CFB, key)
            encrypted_contents = checkin.encode_aes(cipher, contents)

            # Write ahead log: did, owner, security_flag, key, is_deleted
            log = (
                did
                + ","
                + str(user_id)
                + ","
                + str(security_flag)
                + ","
                + b64encode(encrypted_key)
                + ","
                + "False\n"
            )
            doc_metadata[str(did)] = {
                "owner": str(user_id),
                "sec_flag": str(security_flag),
                "key": b64encode(encrypted_key),
                "is_deleted": False,
            }

            with open(path_prefix + did, "w") as f_log:
                f_log.write(encrypted_contents)

            # Delete signed file if user is switching from Integrity to Confidentiality
            try:
                os.remove(path_prefix + did + "_signed")
            except OSError:
                print "No signed file to delete"

            with open("db.log", "a") as db_wal:
                db_wal.write(log)

            response = {
                "status": 200,
                "message": "Checkin Successful",
            }

        # 2 -> Integrity
        if str(security_flag) == "2":
            # Sign document
            signed_contents = b64encode(checkin.sign_document(contents))

            # Write ahead log: did, owner, security_flag, key (empty), is_deleted
            log = (
                did
                + ","
                + str(user_id)
                + ","
                + str(security_flag)
                + ","
                + ","
                + "False\n"
            )
            doc_metadata[str(did)] = {
                "owner": str(user_id),
                "sec_flag": str(security_flag),
                "key": "",
                "is_deleted": False,
            }

            with open(path_prefix + did, "w") as f_log:
                f_log.write(contents)

            with open(path_prefix + did + "_signed", "w") as f_log:
                f_log.write(signed_contents)

            with open("db.log", "a") as db_wal:
                db_wal.write(log)

            response = {
                "status": 200,
                "message": "Checkin Successful",
            }

        return jsonify(response)


class grant(Resource):
    """ Class with grant functionality """

    def post(self):
        """
                Expected response status codes:
                1) 200 - Successfully granted access
                2) 702 - Access denied to grant access
                3) 700 - Other failures
        """
        data = request.get_json()
        # Implement grant functionality

        if data["token"] not in session or session[data["token"]][1]:
            response = {
                "status": 700,
                "message": "Invalid session token in request",
            }

            return jsonify(response)

        user_id = session[data["token"]][0]
        did = data["did"].decode("utf-8")
        # print(doc_metadata)

        if did not in doc_metadata:
            response = {
                "status": 700,
                "message": "Document does not exist!",
            }

            return jsonify(response)

        if doc_metadata[did]["owner"] != user_id:
            response = {
                "status": 702,
                "message": "Access denied to grant access",
            }

            return jsonify(response)

        target_uid = data["target_UID"].decode("utf-8")
        access_type = data["access_type"].decode("utf-8")
        duration = data["duration"].decode("utf-8")
        # print(data)

        grant_dict[did] = dict()
        grant_dict[did] = {
            "target_UID": target_uid,
            "access_type": access_type,
            "duration": duration,
        }
        grant_dict[did]["grant_timestamp"] = int(time.time())
        grant_dict[did]["is_expired"] = False

        with open("grant.log", "a") as grant_wal:
            to_write = [did]
            # to_write.extend(map(str, grant_dict[did].values())) # Explicitly order this.
            to_write.append(grant_dict[did]["target_UID"])
            to_write.append(grant_dict[did]["access_type"])
            to_write.append(grant_dict[did]["duration"])
            to_write.append(str(grant_dict[did]["grant_timestamp"]))
            to_write.append(str(grant_dict[did]["is_expired"]))

            # print(",".join(to_write))
            str_to_write = ",".join(to_write) + "\n"

            grant_wal.write(str_to_write)

        response = {
            "status": 200,
            "message": "Successfully granted access",
        }

        return jsonify(response)


class delete(Resource):
    """ Class with delete functionality """

    def post(self):
        """
                Expected response status codes:
                1) 200 - Successfully deleted the file
                2) 702 - Access denied to delete file
                3) 704 - Delete failed since file not found on the server
                4) 700 - Other failures
        """
        data = request.get_json()
        # Implement delete functionality
        did = data["did"]
        path_prefix = "documents/"

        if data["token"] not in session or session[data["token"]][1]:
            response = {
                "status": 700,
                "message": "Invalid session token in request",
            }

            return jsonify(response)

        user_id = session[data["token"]][0]

        # print(did, user_id)
        # print(doc_metadata[did])

        # Check if file is already deleted
        if doc_metadata[did]["is_deleted"]:
            response = {
                "status": 704,
                "message": "Delete failed since file not found on the server",
            }

            return jsonify(response)

        # Check for deletion access:
        if user_id != doc_metadata[did]["owner"]:
            response = {
                "status": 702,
                "message": "Access denied to delete file",
            }

            return jsonify(response)

        # Check if file is already deleted:
        if doc_metadata[did]["is_deleted"]:
            response = {
                "status": 700,
                "message": "File is already deleted!",
            }

            return jsonify(response)

        try:
            os.remove(path_prefix + did)
            if os.path.exists(path_prefix + did + "_signed"):
                os.remove(path_prefix + did + "_signed")

            response = {
                "status": 200,
                "message": "Delete Successful",
            }

            doc_metadata[did]["is_deleted"] = True
            # Write deletion to log.
            log = (
                did
                + ","
                + str(user_id)
                + ","
                + doc_metadata[did]["sec_flag"]
                + ","
                + doc_metadata[did]["key"]
                + ","
                + str(doc_metadata[did]["is_deleted"])
                + "\n"
            )
            # doc_metadata[str(did)] = { "owner": str(user_id), "sec_flag": str(security_flag),
            # "key": "", "is_deleted": False }
            with open("db.log", "a") as f_log:
                f_log.write(log)
        except OSError:
            response = {
                "status": 704,
                "message": "Delete failed since file not found on the server",
            }

        return jsonify(response)


class logout(Resource):
    """ Class with logout functionality """

    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        data = request.get_json()
        # Implement logout functionality
        # print(data)
        success = data["token"] in session and not session[data["token"]][1]
        if success:
            # session.pop(data["token"], None)
            user_id, _ = session[data["token"]]
            session[data["token"]] = (user_id, True)
            # Write ahead log
            with open("sessions.log", "a") as session_wal:
                session_wal.write(str(data["token"]) + "," + user_id + "," + str(True) + "\n")

            response = {
                "status": 200,
                "message": "Successfully logged out",
            }
        else:
            response = {"status": 700, "message": "Failed to log out"}
        return jsonify(response)


api.add_resource(welcome, "/")
api.add_resource(login, "/login")
api.add_resource(checkin, "/checkin")
api.add_resource(checkout, "/checkout")
api.add_resource(grant, "/grant")
api.add_resource(delete, "/delete")
api.add_resource(logout, "/logout")


# db = open("db.log", "a")


def main():
    """ Run the server """
    # Load sessions, if any.
    if os.path.exists("sessions.log"):
        with open("sessions.log", "r") as sessions_wal:
            for line in sessions_wal:
                token, user_id, is_invalid = line.split(",")
                session[token] = (user_id, True if is_invalid == "True" else False)

    # Build grant_dict from grant log if grant is empty
    if not grant_dict and os.path.exists("grant.log"):
        with open("grant.log", "r") as f_log:
            for line in f_log.readlines():
                values = line.split(",")

                grant_dict[values[0]] = {
                    "target_UID": values[1],
                    "access_type": values[2],
                    "duration": values[3],
                    "grant_timestamp": int(values[4]),
                    "is_expired": True if values[5] == "True" else False,
                }

    # Build doc_metadata from db.log if doc_metadata is empty
    # doc_metadata[did] = { "owner": str(user_id), "sec_flag": security_flag,
    # "key": b64encode(encrypted_key), "is_deleted": False }
    if not doc_metadata and os.path.exists("db.log"):
        with open("db.log", "r") as f_log:
            for line in f_log.readlines():
                values = line.split(",")

                doc_metadata[values[0]] = {
                    "owner": values[1],
                    "sec_flag": values[2],
                    "key": values[3],
                    "is_deleted": True if values[4] == "True" else False,
                }

    print doc_metadata
    print grant_dict
    print session

    secure_shared_service.run(debug=True)


if __name__ == "__main__":
    main()
