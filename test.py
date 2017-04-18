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
    print(1)
    subprocess.run(["make", "clean"])
    subprocess.run(["rm", "-rf", "Makefile"])
    subprocess.run(["rm", "-rf", "util"])
    subprocess.run(["rm", "-rf", "lib"])
    print(2)    
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
        #otpauth://hotp/ece?issuer=uoft&secret=CI2FM6EQCI2FM6EQ&counter=1
        temp = open("student_solution_1", "w")      
        try:
            subprocess.run(["./generateQRcode", "uoft", "ece", "12345678901234567890"], stdout = temp)
        except:
            print("generateQRcode error...")
            time.sleep(3)
            pass
        temp.close()
        
        temp = open("student_solution_1", "r", encoding = "ISO-8859-1")
        content = temp.readlines()
        hotp_p1 = False
        totp_p1 = False
        for line in content:
            print(line)
            if "otpauth://hotp/ece?issuer=uoft&secret=CI2FM6EQCI2FM6EQ&counter=1" in line:
                hotp_p1 = True
                
            if "otpauth://totp/ece?issuer=uoft&secret=CI2FM6EQCI2FM6EQ&period=30" in line:
                totp_p1 = True
        
        if hotp_p1 == False:
            logfile.write("generateQRcode test 1 HOTP failed...\n")
        if totp_p1 == False:
            logfile.write("generateQRcode test 1 TOTP failed...\n")
        if hotp_p1 == True and totp_p1 == True:
            logfile.write("generateQRcode test 1 passed...\n")
        temp.close()



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
        
           
        temp = open("student_solution_2", "r", encoding = "ISO-8859-1")
        content = temp.readlines()
        hotp_p2 = False
        totp_p2 = False
        for line in content:
            if "otpauth://hotp/ece%20department?issuer=u%20of%20t&secret=CI2FM6EQCI2FM6EQ&counter=1" in line:
                hotp_p2 = True
                
            if "otpauth://totp/ece%20department?issuer=u%20of%20t&secret=CI2FM6EQCI2FM6EQ&period=30" in line:
                totp_p2 = True
        
        if hotp_p2 == False:
            logfile.write("generateQRcode test 2 HOTP failed...\n")
        if totp_p2 == False:
            logfile.write("generateQRcode test 2 TOTP failed...\n")
        if hotp_p2 == True and totp_p2 == True:
            logfile.write("generateQRcode test 2 passed...\n")
        temp.close()



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
        
        temp = open("student_solution_3", "r", encoding = "ISO-8859-1")
        content = temp.readlines()
        hotp_p3 = False
        totp_p3 = False
        for line in content:
            if "otpauth://hotp/ece?issuer=uoft&secret=CI2FM6EQVPG66ERU&counter=1" in line:
                hotp_p3 = True
                
            if "otpauth://totp/ece?issuer=uoft&secret=CI2FM6EQVPG66ERU&period=30" in line:
                totp_p3 = True
        
        if hotp_p3 == False:
            logfile.write("generateQRcode test 3 HOTP failed...\n")
        if totp_p3 == False:
            logfile.write("generateQRcode test 3 TOTP failed...\n")
        if hotp_p3 == True and totp_p3 == True:
            logfile.write("generateQRcode test 3 passed...\n")
        temp.close()

            
            

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
                    hotp_s = line.split()[2]
                if line.split()[0] == "TOTP":
                    totp_valid = line.split()[3]
                    totp_s = line.split()[2]
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
            logfile.write("valide failed...")
            time.sleep(5)
        else:
            if hotp_valid == "(valid)":
                logfile.write("HOTP validation success...\n")
            else:
                logfile.write("HOTP failed..." + hotp + " " + hotp_s +"\n")
                
            if totp_valid == "(valid)":
                logfile.write("TOTP validation success...\n")
            else:
                logfile.write("TOTP failed..." + totp + " " + totp_s +"\n")

        temp2.close()
        pass
    
    
    
    
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


















