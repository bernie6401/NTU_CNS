f = open("./Gen_IP.txt", "w")

for i in range(256):
    for j in range(256):
        f.write("140.112."+str(i)+"."+str(j)+"\n")

f.close()