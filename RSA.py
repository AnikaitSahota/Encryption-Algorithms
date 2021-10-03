import gmpy2

class RSA :
	"""class for all RSA calculations.
		Containing key genration and encryption / decryption of messages.
	"""
	def __init__(self , p , q) -> None:
		"""constructor to genrate set of private and public keys for RSA

		Parameters
		----------
		p : int or string
			large prime number
		q : int or string
			large prime number
		"""
		self.public_key , self.private_key = self.key_gen(gmpy2.mpz(p) , gmpy2.mpz(q))				# calculating and storing the public and private RSA keys

	def _fermat_number(self , x : int) -> int :
		"""fermats number for selecting the e value.											# https://www.di-mgt.com.au/rsa_alg.html#note2

		Parameters
		----------
		x : int
			value judging the i th value of fermat's prime

		Returns
		-------
		int
			x th fermat's prime
		"""
		return 2 ** (2 ** x) + 1

	def key_gen(self , p , q) :
		"""function to genrate the key pairs using the provided pair of large prime numebers

		Parameters
		----------
		p : gmpy2.mpz
			large prime numebr
		q : gmpy2.mpz
			large prime number

		Returns
		-------
		key pair
			public key and private key
		"""
		n = p * q																						# n is the product of the two chosen prime numbers, given p and q
		totient_n = (p-1) * (q-1)																		# calculating totient(n), which is, product of p-1 and q-1

		# fact : co-prime e > totient_n would work perfectly for RSA algo, however it would give a computational overhead while encryption and provide no extra security; hence it is kept lower than totient_n
		# e = totient_n -1																				# this is insecure, as it have high-probability of having same value for e and d ; making private key vulnerable
		e = gmpy2.mpz(self._fermat_number(4))															# small fermat's prime speeds up the encryption of messaage and guarantees with high-probability that d is large enough to prevent various attack.
		# e = gmpy2.mpz(self._fermat_number(0))															# = 3 ; more smaller fermat's prime doesn't provide any security as message ^ e (small e) is easily gussed
		# e = gmpy2.next_prime(totient_n // 2)															# this can be used; but it is insecure as it involves totient_n in calculation of a public variable (i.e., e) that can lead to disclosure of totient_n and then d itself and is comutationally expensive


		if(totient_n % e == 0 or e >= totient_n) :														# this ensures e follows the range crieteria (can be ingnore as mentioned in line 52) of RSA and coprime property; however practically if e = 65537 is not coprime with totient_n then p & q are genrated again. reference : https://www.johndcook.com/blog/2018/12/12/rsa-exponent/
			e = totient_n - 1

		d = gmpy2.invert(e, totient_n)																	# calculating the d ; e.d = 1 (mod totient_n)

		# (n , e) is public key
		# (n , d) or (p , q , d) is private key
		return (n , e) , (n , d) 																		# returning public and private key

	def _message_resolver(self , key : tuple , message : gmpy2.mpz) -> gmpy2.mpz :
		"""function to resolve the message using the key

		Parameters
		----------
		key : tuple
			tupple of modulu (i.e., n) and exponential (i.e., e or d) ; used to resolve the message
		message : gmpy2.mpz
			message to be resolveed

		Returns
		-------
		gmpy2.mpz
			resolved message
		"""
		mod = key[0]
		exp = key[1]
		return gmpy2.powmod(message, exp, mod)

	def encrypt(self , m : gmpy2.mpz) -> gmpy2.mpz :
		"""function to encrypt the message (m) using the public key

		Parameters
		----------
		m : gmpy2.mpz
			message to be encrypted

		Returns
		-------
		gmpy2.mpz
			encrypted message i.e., cipher text
		"""
		# n = key[0] ; e = key[1]
		# return gmpy2.powmod(m, e, n)
		return self._message_resolver(self.public_key , m)


	def decrypt(self , c) :
		"""function to decrypt the cipher text (c) using the private key

		Parameters
		----------
		c : gmpy2.mpz
			cipher text to be decrypted

		Returns
		-------
		gmpy2.mpz
			decrypted cipher text i.e., message
		"""
		# n = key[0] ; d = key[1]
		# return gmpy2.powmod(c, d, n)
		return self._message_resolver(self.private_key , c)

if __name__ == '__main__' :
	print("Enter the numbers in order of p, q, m and every number in a new line")
	p = input()
	q = input()
	m = gmpy2.mpz(input())

	obj = RSA(p , q)

	c = obj.encrypt(m)

	print('c' , c)
	print('e' , obj.public_key[1])
	print('d' , obj.private_key[1])
	print('n' , obj.public_key[0])

	m_hat = obj.decrypt(c)

	print('m' , m_hat)
	print('c' , c)
	print('d' , obj.private_key[1])
	print('n' , obj.public_key[0])

	print()
	if(m == m_hat) :
		print("Yes, the original message and deciphered message are same")
	else :
		print("No, the original message and deciphered message are different")