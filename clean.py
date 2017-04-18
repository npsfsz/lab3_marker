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
