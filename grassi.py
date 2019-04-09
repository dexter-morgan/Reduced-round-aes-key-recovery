import random
import sys
sys.path.append('./')

from aes import AES_128

def get_goodpairs(key):
	crypt = AES_128(5)
	crypt.key = key
	x = [chr(i) for i in range(256)]
	pl1 = [chr(0) for _ in range(16)]
	pl2 = [chr(0) for _ in range(16)]
	a = range(256)
	b, c, d = a[:], a[:], a[:]
	random.shuffle(b)
	random.shuffle(c)
	random.shuffle(d)


	for i1 in range(256):
		for i2 in range(i1+1, 256):
			# print(i1,i2)
			for j1 in range(256):
				for j2 in range(j1+1,256):
					for k1 in range(256):
						for k2 in range(k1+1,256):
							for l1 in range(256):
								for l2 in range(l1+1,256):
									pl2[0], pl2[5], pl2[10], pl2[15] = x[a[i2]], x[b[j2]], x[c[k2]], x[d[l2]]
									pl1[0], pl1[5], pl1[10], pl1[15] = x[a[i1]], x[b[j1]], x[c[k1]], x[d[l1]]
									
									c1 = crypt.cipher(''.join(pl1))
									c2 = crypt.cipher(''.join(pl2))

									if ((c1[0]==c2[0]) and (c1[7]==c2[7]) and (c1[10]==c2[10]) and (c1[13]==c2[13]) and (pl1 != pl2)):
										return pl1, pl2	

key = "2b7e151628aed2a6abf7158809cf4f3c".decode('hex')
p1, p2 = get_goodpairs(key)
print(p1,p2)


keys_0, keys_5, keys_10, keys_15 = [], [], [], []
for k in range(0, 256):
	keys_0.append(k)
	keys_5.append(k)
	keys_10.append(k)
	keys_15.append(k)

for k0 in keys_0:
	for k5 in keys_5:
		for k10 in keys_10:
			for k15 in keys_15:
				key_guess = [chr(k0)] + [chr(0)]*4 + [chr(k5)] + [chr(0)]*4 + [chr(k10)] + [chr(0)]*4 + [chr(k15)]
					one_round_crypt = AES_128(1, True)
					one_round_crypt.key = key_guess
					xp = one_round_crypt.cipher(''.join(p1))
					yp = one_round_crypt.cipher(''.join(p2))

					zp = xp[:]
					wp = yp[:]
					zp[4]  = yp[4]
					zp[12] = yp[12]
					wp[4]  = xp[4]
					wp[12] = xp[12]
					p3 = one_round_crypt.inv_cipher(''.join(zp))
					p4 = one_round_crypt.inv_cipher(''.join(wp))

					crypt = AES_128(5)
					crypt.key = key_guess
					c3 = crypt.cipher(''.join(p3))
					c4 = crypt.cipher(''.join(p4))
					if ((c3[0]==c4[0]) and (c3[7]==c4[7]) and (c3[10]==c4[10]) and (c3[13]==c4[13])):
						print(key_guess)
						print("Grassi: Success")
						break




