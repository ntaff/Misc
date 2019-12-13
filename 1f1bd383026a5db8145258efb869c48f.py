def decrypt(l):
  key = l[:2]
  encr = l[2:]
  l=[]
  if (len(encr)%2) == 0:
    tailleencr = len(encr)/2
  else:
    tailleencr = (len(encr)/2)+1
  tailleencr = int(tailleencr)
  for i in range(tailleencr):
    l.append(encr[(i*2):(i*2+2)])
  l2=[]
  key2 = int(key,16)
  for i in range (len(l)):
    encr2 = int(l[i],16)
    decr = encr2 ^ key2
    azerty = str(chr(decr))
    l2.append(azerty)
  return l2

file = open('encrypted.txt', 'r')
lll=[]
for line in file.readlines():

  line = line.rstrip()
  liste = decrypt(line)
  makeitastring = ''.join(map(str, liste))
  lll.append(makeitastring)
resultat = ''.join(map(str, lll))
print(resultat)

#NB2HI4DTHIXS6Y3UMYXGQZLYOBZGK43TN4XGM4RPGU3TSODDME2DOZDBMNSTKYZVMU3GIMZVGI4TMOJQMM4DMMZTG42QU===
