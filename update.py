import random
import sys
sys.path.append('./')

from aes import AES_128

pre_computed_table = [[[None] for _ in range(256)] for _ in range(256) for _ in range(256)]

def pre_compute(crypt):
	for a in range(256):
		for b in range(a+1, 255):
			for k in range(256):
				t = crypt.get_sbox(k)^crypt.get_sbox(a^k)^crypt.get_sbox(b^k)
				c = crypt.get_inv_sbox(t)^k
				if b < c: pre_computed_table[a][b][c] = k

def get_goodpairs(key):
	crypt = AES_128(5)
	crypt.key = key
	x = [chr(i) for i in range(256)]
	pl1 = [chr(0) for _ in range(16)]
	pl2 = [chr(0) for _ in range(16)]
	a = range(256)
	b, c = a[:], a[:]
	random.shuffle(b)
	random.shuffle(c)

	LIMIT = 2**21

	good_pairs, count = [], 0
	for i1 in range(256):
		for i2 in range(i1+1, 256):
			# print(i1,i2)
			for j1 in range(256):
				for j2 in range(j1+1,256):
					for k1 in range(256):
						for k2 in range(k1+1,256):
							count += 1

							pl2[5], pl2[10], pl2[15] = x[a[i2]], x[b[j2]], x[c[k2]]
							pl1[5], pl1[10], pl1[15] = x[a[i1]], x[b[j1]], x[c[k1]]
							
							c1 = crypt.cipher(''.join(pl1))
							c2 = crypt.cipher(''.join(pl2))

							if ((c1[0]==c2[0]) and (c1[7]==c2[7]) and (c1[10]==c2[10]) and (c1[13]==c2[13]) and (pl1 != pl2)):
								good_pairs.append([pl1, pl2])

							if count == LIMIT:
								return good_pairs
	return good_pairs

def is_mixture(crypt, k, x, y, z, w, ind):
	if ind == 0: key_guess = [chr(k)] + [chr(0)]*15
	elif ind == 4: key_guess = [chr(0)]*5 + [chr(k)] + [chr(0)]*10
	elif ind == 8: key_guess = [chr(0)]*10 +  [chr(k)] + [chr(0)]*5
	elif ind == 12: key_guess = [chr(0)]*15 + [chr(k)]
	else: return False

	c_x = crypt.cipher(''.join(x))
	c_y = crypt.cipher(''.join(y))
	c_z = crypt.cipher(''.join(z))
	c_w = crypt.cipher(''.join(w))

	return c_x[ind]^yc_[ind] == c_z[ind]^c_w[ind]


def update_124(all_good_pairs):
	one_round_crypt = AES_128(1, True)
	len_gp = len(all_good_pairs) # 2**15

	keys_0, keys_5, keys_10, keys_15 = [], [], [], []

	for i in range(len_gp):
		for j in range(i+1, len_gp):
			x, y = all_good_pairs[i]
			z, w = all_good_pairs[j]

			for k in range(256):
				if is_mixture(one_round_crypt, k, x, y, z, w, 0): keys_0.append(k)
				if is_mixture(one_round_crypt, k, x, y, z, w, 4): keys_5.append(k)
				if is_mixture(one_round_crypt, k, x, y, z, w, 8): keys_10.append(k)
				if is_mixture(one_round_crypt, k, x, y, z, w, 12): keys_15.append(k)

			for k0 in keys_0:
				for k5 in keys_5:
					for k10 in keys_10:
						for k15 in keys_15:
							key_guess = [chr(k0)] + [chr(0)]*4 + [chr(k5)] + [chr(0)]*4 + [chr(k10)] + [chr(0)]*4 + [chr(k15)]
							one_round_crypt.key = ''.join(key_guess)

							c_x = one_round_crypt.cipher(''.join(x))
							c_y = one_round_crypt.cipher(''.join(y))
							c_z = one_round_crypt.cipher(''.join(z))
							c_w = one_round_crypt.cipher(''.join(w))

							if (c_x[0]^yc_[0] == c_z[0]^c_w[0]) and (c_x[4]^yc_[4] == c_z[4]^c_w[4]) and (c_x[8]^yc_[8] == c_z[8]^c_w[8]) and (c_x[12]^yc_[12] == c_z[12]^c_w[12]):
								return key_guess


def update_34(all_good_pairs):
	one_round_crypt = AES_128(1, True)
	len_gp = len(all_good_pairs) # 2**15

	keys_0, keys_5, keys_10, keys_15 = [], [], [], []

	for i in range(len_gp):
		for j in range(i+1, len_gp):
			x, y = all_good_pairs[i]
			z, w = all_good_pairs[j]

			quartet_0 = [y[0]^x[0], z[0]^x[0], w[0]^x[0]]
			quartet_4 = [y[4]^x[4], z[4]^x[4], w[4]^x[4]]
			quartet_8 = [y[8]^x[8], z[8]^x[8], w[8]^x[8]]
			quartet_12 = [y[12]^x[12], z[12]^x[12], w[12]^x[12]]

			quartet_0.sort()
			quartet_4.sort()
			quartet_8.sort()
			quartet_12.sort()

			k0 = pre_computed_table[quartet_0[0]][quartet_0[1]][quartet_0[2]]^x[0]
			k5 = pre_computed_table[quartet_4[0]][quartet_4[1]][quartet_4[2]]^x[4]
			k10 = pre_computed_table[quartet_8[0]][quartet_8[1]][quartet_8[2]]^x[8]
			k15 = pre_computed_table[quartet_12[0]][quartet_12[1]][quartet_12[2]]^x[12]

			key_guess = [chr(k0)] + [chr(0)]*4 + [chr(k5)] + [chr(0)]*4 + [chr(k10)] + [chr(0)]*4 + [chr(k15)]
			return key_guess


key = "2b7e151628aed2a6abf7158809cf4f3c".decode('hex')

all_good_pairs = get_goodpairs(key)
print(all_good_pairs)

guessed = update_124(all_good_pairs)
print(guessed)

if (guessed[0] == key[0]) and (guessed[4] == key[4]) and (guessed[8] == key[8]) and (guessed[15] == key[15]):
	print("Success")
