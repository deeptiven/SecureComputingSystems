import crypt
import os
import shutil
import sys

option = int(raw_input("Enter '1' for creating new user or '2' for login or '3' for updating password or "
                       "'4' for deleting user account: "))

# Real values
SHADOW = "/etc/shadow"
PASSWD = "/etc/passwd"
HOME = "/home/"
SALT_PASS_INDEX = 2

# Fake values
# SHADOW = "./shadow"
# PASSWD = "./passwd"
# HOME = "./home/"
# SALT_PASS_INDEX = 1

# print SHADOW
# print PASSWD

if option == 1:
    uname = raw_input("Enter username: ")
    exists = False

    with open(SHADOW,'r') as fp:         # Opening shadow file in read mode
        for line in fp:                         # Enumerating through all the enteries in shadow file
            temp = line.split(':')

            if temp[0] == uname:                  # checking whether entered username exist or not
                sys.exit("FAILURE: user " + uname + " already exists")

    passwd = raw_input("Enter Password for the " + uname + " : ")
    salt = raw_input("Enter the salt: ")
    initial_token = raw_input("Enter initial token: ")

    hardPwd = passwd + initial_token

    hash = crypt.crypt(hardPwd,'$6$'+salt)         # 		generating hash
    line = uname+':'+hash+":17710:0:99999:7:::"

    file1 = open(SHADOW,"a+")              # Opening shadow file in append+ mode
    file1.write(line+'\n')			    # Making hash entry in the shadow file
    file1.close()

    try:
        os.mkdir(HOME + uname)	            # Making home file for the user
    except:
        print("Directory: " + HOME + uname+ " already exist")

    file2 = open(PASSWD,"a+")		    # Opening passwd file in append+ mode
    count = 1000

    with open(PASSWD,'r') as f:          # Opening passwd file in read mode
        for line in f:
            temp1 = line.split(':')

            # checking number of existing UID
            while int(temp1[3]) >= count and int(temp1[3]) < 65534:
                count = int(temp1[3]) + 1           # assigning new uid = 1000+number of UIDs +1

    count = str(count)
    str1 = uname + ':x:' + count + ':' + count + ':,,,:' + HOME + uname + ':/bin/bash' + '\n'

    file2.write(str1)                           # creating entry in passwd file for new user
    file2.close()

    print("SUCESS: " + uname + " created")

if option == 2:
    uname = raw_input("Enter username : ")

    exists = False
    lines_to_write = []
    user_data = []
    data = []

    with open(SHADOW,'r') as fp:         # Opening shadow file in read mode
        for line in fp:                         # Enumerating through all the enteries in shadow file
            user_data=line.split(':')
            lines_to_write.append(user_data[:])

            if user_data[0] == uname:                  # checking whether entered username exist or not
                exists = True
                data = user_data[:]

    if not exists:
        sys.exit("FAILURE: User " + uname + " does not exist")

    passwd = raw_input("Enter Password for the "+uname+" : ")
    current_token = raw_input("Enter the current token: ")
    next_token = raw_input("Enter the next token: ")

    hardPwd = passwd + current_token
    newHardPwd = passwd + next_token

    salt_and_pass = (data[1].split('$'))  # retrieving salt against the user
    salt = salt_and_pass[SALT_PASS_INDEX]
    result = crypt.crypt(hardPwd, '$6$' + salt)  # calculating hash via salt and password entered by user

    if result != data[1]:
        sys.exit("FAILURE: either passwd or token incorrect")

    with open(SHADOW, 'w') as fp:
        for line in lines_to_write:
            if line[0] == uname:
                line[1] = crypt.crypt(newHardPwd,'$6$'+salt)

            fp.write(":".join(line))

    print "SUCCESS: Login successful."

if option == 3:
    uname = raw_input("Enter username : ")

    exists = False
    lines_to_write = []
    user_data = []
    data = []

    with open(SHADOW, 'r') as fp:  # Opening shadow file in read mode
        for line in fp:  # Enumerating through all the enteries in shadow file
            user_data = line.split(':')
            lines_to_write.append(user_data[:])

            if user_data[0] == uname:  # checking whether entered username exist or not
                exists = True
                data = user_data[:]

    if not exists:
        sys.exit("FAILURE: User " + uname + " does not exist")

    passwd = raw_input("Enter Password for the " + uname + ": ")
    current_token = raw_input("Enter the current token: ")

    hardPwd = passwd + current_token

    salt_and_pass = (data[1].split('$'))  # retrieving salt against the user
    salt = salt_and_pass[SALT_PASS_INDEX]
    result = crypt.crypt(hardPwd, '$6$' + salt)  # calculating hash via salt and password entered by user

    if result != data[1]:
        sys.exit("FAILURE: either passwd or token incorrect")

    next_token = raw_input("Enter the next token: ")
    new_passwd = raw_input("Enter new password for " + uname + ": ")
    confirm_passwd = raw_input("Confirm password for the " + uname + ": ")

    if new_passwd != confirm_passwd:
        sys.exit("Entered passwords do not match!")

    newHardPwd = new_passwd + next_token

    new_salt = raw_input("Enter new salt for the " + uname + ": ")

    with open(SHADOW, 'w') as fp:
        for line in lines_to_write:
            if line[0] == uname:

                line[1] = crypt.crypt(newHardPwd,'$6$'+ new_salt)


            fp.write(":".join(line))

    print "SUCCESS: Password update successful."

if option == 4:
    uname = raw_input("Enter username : ")

    exists = False
    lines_to_write = []
    user_data = []
    data = []

    with open(SHADOW, 'r') as fp:  # Opening shadow file in read mode
        for line in fp:  # Enumerating through all the enteries in shadow file
            user_data = line.split(':')
            lines_to_write.append(user_data[:])

            if user_data[0] == uname:  # checking whether entered username exist or not
                exists = True
                data = user_data[:]

    if not exists:
        sys.exit("FAILURE: User " + uname + " does not exist")

    passwd = raw_input("Enter Password for the " + uname + ": ")
    current_token = raw_input("Enter the current token: ")

    hardPwd = passwd + current_token

    salt_and_pass = (data[1].split('$'))  # retrieving salt against the user
    salt = salt_and_pass[SALT_PASS_INDEX]
    result = crypt.crypt(hardPwd, '$6$' + salt)  # calculating hash via salt and password entered by user

    if result != data[1]:
        sys.exit("FAILURE: either passwd or token incorrect")

    # Clean up: Remove entry from SHADOW
    with open(SHADOW, 'w') as fp:
        for line in lines_to_write:
            if line[0] == uname:
                continue

            fp.write(":".join(line))

    # Clean up: Remove entry from PASSWD
    lines_to_write = []
    with open(PASSWD, 'r') as fp:
        for line in fp:
            lines_to_write.append(line.split(":"))

    with open(PASSWD, "w") as fp:
        for line in lines_to_write:
            if line[0] == uname:
                continue

            fp.write(":".join(line))

    # Clean up: Remove home directory
    try:
        shutil.rmtree(HOME + uname)
    except:
        print("Directory: " + HOME + uname+ " already deleted")

    print "SUCCESS: user " + uname + " Deleted"
