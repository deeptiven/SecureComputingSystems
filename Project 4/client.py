""" Client """
import certifi
import hashlib
import json
import os
import shutil
from base64 import b64decode, b64encode

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

GT_USERNAME = "dvenkatesh7"
SERVER_NAME = "secure-shared-store"

CLIENT_ID = os.getcwd().split("/")[-1]
NODE_CERT = "certs/" + CLIENT_ID + ".crt"
NODE_KEY = "certs/" + CLIENT_ID + ".key"
CA_CERT = "certs/CA.crt"

session_token = {"user_id": "", "token": ""}
checked_out_files = dict()

""" <!!! DO NOT MODIFY THIS FUNCTION !!!>"""


def post_request(server_name, action, body, node_certificate, node_key):
    """
        node_certificate is the name of the certificate file of the client
        node (present inside certs).
        node_key is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = "https://{}/{}".format(server_name, action)
    request_headers = {"Content-Type": "application/json"}
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
    )
    with open(GT_USERNAME, "w") as file_handler:
        file_handler.write(response.content)
    return response


# """ You can begin modification from here"""


def is_status_200(response):
    """ Check if the response status is 200"""

    json_response = json.loads(response.content)
    # print json_response["status"]

    return json_response["status"] == 200


def login(user_id, pvt_key_file):
    """
        # Accept the
         - user-id
         - name of private key file(should be
        present in the userkeys folder) of the user.
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (action = 'login') using
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """
    statement = (
        CLIENT_ID + " as " + str(user_id) + " logs into the Server"
    )

    # Sign statement
    try:
        signed_statement = b64encode(sign_message(pvt_key_file, statement))
    except (OSError, IOError):
        print "Couldn't sign stagement"
        return False

    action = "login"
    body = {
        "user_id": user_id,
        "statement": statement,
        "signed_statement": signed_statement,
    }

    try:
        response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)
    except requests.exceptions.SSLError as err:
        # Fix SSL Error - https://incognitjoe.github.io/adding-certs-to-requests.html
        print "SSL Error. Adding custom certs to Certifi store..."
        cafile = certifi.where()
        # print cafile
        with open(CA_CERT, 'rb') as infile:
            customca = infile.read()
        with open(cafile, 'ab') as outfile:
            outfile.write(customca)

        # Try again after updating contents of the certificate file used by certifi
        response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)        

    if not is_status_200(response):
        return False

    session_token["user_id"] = user_id
    session_token["token"] = json.loads(response.content)["session_token"]

    return True


def checkin(did, security_flag):
    """
        # Accept the
         - DID
         - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin')
        using post_request().
        The request body should contain the required parameters to ensure the file
        is sent to the server.
    """
    action = "checkin"
    path_prefix = "documents/checkin/"
    checkout_path_prefix = "documents/checkout/"

    # Check if file is currently checked out. "Move" it to checkin folder.
    if os.path.exists(checkout_path_prefix + did):
        # Delete file in checkin path if present:
        try:
            shutil.move(checkout_path_prefix + did, path_prefix + did)
        except (OSError, IOError):
            print "Failed to move the file"
            return

    # Read contents of file to send to server
    try:
        with open(path_prefix + did, "r") as file_handler:
            contents = file_handler.read()
    except (OSError, IOError):
        print "Couldn't read contents of file to send to server"
        return False

    # Request body: Always include the session_token
    body = {
        "did": did,
        "security_flag": str(security_flag),
        "contents": b64encode(contents),
        "token": session_token["token"],
    }

    response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)

    success = is_status_200(response)

    if success:
        checked_out_files.pop(did, None)

    return success


def checkout(did):
    """
        # Accept the DID.
        Send request to server with required parameters (action = 'checkout') using post_request()
    """
    action = "checkout"
    path_prefix = "documents/checkout/"

    body = {"did": did, "token": session_token["token"]}
    response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)

    if not is_status_200(response):
        return False

    contents = json.loads(response.content)

    # Write contents to file
    try:
        with open(path_prefix + did, "w") as file_handler:
            file_handler.write(b64decode(contents["contents"]))
    except (OSError, IOError):
        print "Could not write contents to file"
        return False

    checked_out_files[did] = hashlib.md5(b64decode(contents["contents"])).hexdigest()

    return True


def grant(did, target_uid, access_type, duration):
    """
        # Accept the
         - DID
         - target user to whom access should be granted (0 for all user)
         - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
         - time duration (in seconds) for which acess is granted
        Send request to server with required parameters (action = 'grant') using post_request()
    """
    action = "grant"
    body = {
        "did": did,
        "target_UID": target_uid,
        "access_type": access_type,
        "duration": duration,
        "token": session_token["token"],
    }

    response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)

    return is_status_200(response)


def delete(did):
    """
        # Accept the DID to be deleted.
        Send request to server with required parameters (action = 'delete')
        using post_request().
    """

    action = "delete"
    body = {"did": did, "token": session_token["token"]}
    response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)

    return is_status_200(response)


def logout():
    """
        # Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    """
    body = {"user_id": session_token["user_id"], "token": session_token["token"]}

    # Checkin modified/checked out file(s) in session:
    checkin_success_dids = []

    for did, md5_hash_val in checked_out_files.items():
        # Check if file has changed and checkin if it has changed
        try:
            with open("documents/checkout/" + did, "r") as checkedout_file:
                contents = checkedout_file.read()
                contents_md5 = hashlib.md5(contents).hexdigest()
        except (OSError, IOError):
            print "Couldn't read checkedout file: " + "documents/checkout/" + did
            continue
 
        if md5_hash_val == contents_md5:
            continue

        checkin_success = checkin(did, "2")

        # Handle response
        if not checkin_success:
            print "Error checking in modified/checkout files"

        checkin_success_dids.append(did)

    for did in checkin_success_dids:
        checked_out_files.pop(did, None)

    # Clean up checkout folder
    try:
        for filename in os.listdir("documents/checkout/"):
          os.remove(os.path.join("documents/checkout/", filename))
    except (IOError, OSError):
        print "Failed to clean up checkout folder"

    action = "logout"
    response = post_request(SERVER_NAME, action, body, NODE_CERT, NODE_KEY)

    status = is_status_200(response)
    if not status:
        return
    else:
        exit()  # exit the program


def main():
    """
        # Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indexes as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    while True:
        # Login
        user_id = raw_input("\nEnter user ID: ")
        user_private_key = raw_input("\nEnter filename of user's private key: ")

        # login_response = login(user_id, user_private_key)
        login_success = login(user_id, user_private_key)

        # login_success = json.loads(login_response)["status"] == 200

        if not login_success:
            print "Login unsuccessful. Try again\n"
            continue
            # break

        options_map = {
            "1": checkin,
            "2": checkout,
            "3": grant,
            "4": delete,
            "5": logout,
        }

        while True:
            print "\n1. Checkin\n2. Checkout\n3. Grant\n4. Delete\n5. Logout\n"

            option = raw_input("\nSelect options from 1 - 5: ")

            print "\nOption chosen: " + options_map[option].func_name.title() + "\n"

            if option == "5":
                options_map[option]()

                print "Logout failed\n"
                exit()

            document_name = raw_input("\nEnter document name: ")

            if option == "1":
                security_flag = raw_input("\nEnter security flag: ")

                result = options_map[option](document_name, security_flag)

            if option == "2":
                result = options_map[option](document_name)

            if option == "3":
                target_user = raw_input("\nEnter the user to be granted access: ")
                access_right = raw_input("\nEnter the type of access to be granted: ")
                time_duration = raw_input("\nEnter the time duration for the access: ")

                result = options_map[option](
                    document_name, target_user, access_right, time_duration
                )

            if option == "4":
                result = options_map[option](document_name)

            if result:
                print options_map[option].func_name.title() + " successful!\n"
            else:
                print options_map[option].func_name.title() + " unsuccessful!\n"


def sign_message(pvt_key_file, message):
    """
        Sign the message using the user's private key and return the signed message
    """
    digest = SHA256.new(message)

    # Read private key from file
    try:
        with open("userkeys/" + pvt_key_file, "rb") as file_handler:
            private_key = RSA.importKey(file_handler.read())
    except (OSError, IOError), e:
        raise e

    # Load private key and sign message
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest)

    private_key = None  # 'Discard' the private key - garbage collected. 

    return sig


if __name__ == "__main__":
    main()
