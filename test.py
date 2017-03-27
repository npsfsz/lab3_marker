#!/usr/bin/python3.5

import os
import subprocess
import filecmp
import time

dir_path = os.path.dirname(os.path.realpath(__file__))
test_path = dir_path+"/test"
print("Initial Directory " + dir_path)
for x in os.walk(dir_path, topdown=True):
    os.chdir(x[0])
    print("#################################################################")
    print("Changing Directory to " + os.path.dirname(os.path.realpath(__file__)))
    
    if os.path.dirname(os.path.realpath(__file__)) == dir_path:
        print("root dir, skip this ...")
        continue

    if (dir_path + "/.git") in os.path.dirname(os.path.realpath(__file__)):
        print("git dir, skip ...")
#        time.sleep(1)
        continue
    if (dir_path + "/test") in os.path.dirname(os.path.realpath(__file__)):
        print("test dir, skip ...")
#        time.sleep(1)
        continue    
        
        
    logfile = open("logfile", "w")
    if os.path.isfile("README") == True and os.path.getsize("README") > 0:
        f = open("README")
        first_student = f.readline()
        print(first_student, file = logfile)
        
        second_student = f.readline()
        print(second_student, file = logfile)
        #for the bad bois who dont print their names in two lines
        thrid_line = f.readline()
        print(thrid_line, file = logfile)
        
    elif os.path.isfile("README.txt") == True and os.path.getsize("README.txt") > 0:
        f = open("README.txt", encoding="ISO-8859-1")
        first_student = f.readline()
        print(first_student, file = logfile)
        
        second_student = f.readline()
        print(second_student, file = logfile)        
        #for the bad bois who dont print their names in two lines
        thrid_line = f.readline()
        print(thrid_line, file = logfile)
        

    subprocess.run(["cp", "-rf", dir_path + "/test/Makefile", "."], stdout = logfile)
    subprocess.run(["cp", "-rf", dir_path + "/test/util", "."], stdout = logfile)
    subprocess.run(["cp", "-rf", dir_path + "/test/lib", "."], stdout = logfile)
    """
    os.system("cp -rf " + dir_path + "/test/Makefile" + " ." )
    os.system("cp -rf " + dir_path + "/test/util" + " ." )
    os.system("cp -rf " + dir_path + "/test/lib" + " ." )
    """
    print("finished copying required files...", file = logfile)
    
#    os.system("make clean")
    subprocess.run("make")
#    os.system("make")
        
        
    if os.path.isfile("generateQRcode") == True and os.path.getsize("generateQRcode") > 0:
  
        #base case: no spaces in issuer and account name, secret only number
        #generateQRcode uoft ece 12345678901234567890
        temp = open("student_solution_1", "w")      
        try:
            subprocess.run(["./generateQRcode", "uoft", "ece", "12345678901234567890"], stdout = temp)
        except:
            print("generateQRcode error...")
            time.sleep(3)
            pass
        temp.close()
        if filecmp.cmp("../test/testcase/generateQRcode.basecase", "student_solution_1"):
            logfile.write("generateQRcode test 1 passed...\n")
        else:
            logfile.write("generateQRcode test 1 failed...\n")



        #spaces in issuer and account name, secret only number
        # generateQRcode "u of t" "ece department" 12345678901234567890
        temp = open("student_solution_2", "w")    
        try:  
            subprocess.run(["./generateQRcode", "u of t", "ece department", "12345678901234567890"], stdout = temp)
        except:
            print("generateQRcode error...")
            time.sleep(3)
            pass
        temp.close()        
        if filecmp.cmp("../test/testcase/generateQRcode.space_in_name", "student_solution_2"):
            logfile.write("generateQRcode test 2 passed...\n")
        else:
            logfile.write("generateQRcode test 2 failed...\n")



        #no space, hex secret
        #generateQRcode uoft ece 1234567890ABCDEF1234
        temp = open("student_solution_3", "w")      
        try:
            subprocess.run(["./generateQRcode", "uoft", "ece", "1234567890ABCDEF1234"], stdout = temp)
        except:
            print("generateQRcode error...")
            time.sleep(3)
            pass
        temp.close()        
        
        if filecmp.cmp("../test/testcase/generateQRcode.hex_secret", "student_solution_3"):
            logfile.write("generateQRcode test 3 passed...\n")
        else:
            logfile.write("generateQRcode test 3 failed...\n")
            
            

        pass
        
    if os.path.isfile("validateQRcode") == True and os.path.getsize("validateQRcode") > 0:
        #validate qr code test
        #generateValue 98765432109876543210
        #check hotp and totp values
        temp = open("solution_4", "w")
        subprocess.run([test_path + "/util/generateValues", "98765432109876543210"], stdout = temp)
        temp.close()
        temp = open("solution_4", "r")
        first_line = temp.readline()

        hotp = first_line.split()[2]

        
        second_line = temp.readline()

        totp = second_line.split()[2]

        temp.close()

        temp2 = open("student_solution_4", "w")
        try:
            subprocess.run(["./validateQRcode", "98765432109876543210", str(hotp), str(totp)], stdout = temp2)
        except:
            print("validate error, i cry")
            time.sleep(3)
            pass
        temp2.close()

        temp2 = open("student_solution_4", "r")
        content = temp2.readlines()
        error = False
        
        hotp_valid = None
        totp_valid = None
        
        for line in content:
            if len(line) > 5:
#                print(line)
                if line.split()[0] == "HTOP":
                    hotp_valid = line.split()[3]

                if line.split()[0] == "TOTP":
                    totp_valid = line.split()[3]
  
        if hotp_valid == None or totp_valid == None:
            error = True
        """        
        #third line, hotp
        if len(content[2].strip()) >= 4:
            hotp_valid = content[2].split()[3]
        else:
            print("format error!", file = logfile)
        #forth line, totp
        if len(content[3].strip()) >= 4:
            totp_valid = content[3].split()[3]
        else:
            print("format error!", file = logfile)
        """
        if error == True:
            print("I hit a error")
            time.sleep(5)
        else:
            if hotp_valid == "(invalid)":
                logfile.write("HOTP validation failed...\n")
            elif totp_valid == "(invalid)":
                logfile.write("TOTP validation failed...\n")
            else:
                logfile.write("validateQRcode passed...\n")

        temp2.close()
        pass
    
    

    subprocess.run(["make", "clean"], stdout = logfile)
    subprocess.run(["rm", "-rf", "Makefile"], stdout = logfile)
    subprocess.run(["rm", "-rf", "util"], stdout = logfile)
    subprocess.run(["rm", "-rf", "lib"], stdout = logfile)
    """    
    os.system("make clean")
    os.system("rm -rf Makefile")
    os.system("rm -rf util")
    os.system("rm -rf lib")
    """    
    print("finished deleting testing files", file = logfile)
    logfile.close()
"""    for file in os.listdir("."):
        print("Current dir has file " + file)
"""        


















